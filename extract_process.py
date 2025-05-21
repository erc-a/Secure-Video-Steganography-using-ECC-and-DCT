import os
import cv2
import numpy as np
from PIL import Image
import helpers as steg_helpers
from cryptography.hazmat.primitives import serialization

# Import fungsi-fungsi dari config_and_setup
from config_and_setup import (
    bytes_ke_bitstream, bitstream_ke_bytes, bitstream_ke_int,
    dekripsi_aes_gcm, deserialisasi_kunci_publik_ecc_compressed, buat_shared_secret_ecdh, 
    derive_kunci_aes_dari_shared_secret, hitung_sha3_256, proses_frame_qim_dct,
    setup_kunci_ecc
)

# --- Helper Function untuk Error ---
def print_error_and_exit_extract(message, cap_to_release=None): 
    print(f"  Error Kritis Ekstraksi: {message}")
    if cap_to_release and cap_to_release.isOpened(): cap_to_release.release()

# --- Fungsi Ekstraksi Utama (Grayscale, SHA3, ECC-AES) ---
def ekstraksi_gambar_video_final(path_stego_video, path_gambar_output, 
                                 delta_kuantisasi, num_ac_coeffs, 
                                 kunci_privat_ecc_penerima, 
                                 bits_untuk_dimensi=16):
    print(f"\n=== MEMULAI PROSES EKSTRAKSI GAMBAR DARI VIDEO ===")
    print(f"  Stego Video: '{path_stego_video}'")
    print(f"  Parameter: DELTA={delta_kuantisasi}, Koefisien AC per Blok={num_ac_coeffs}")

    cap = cv2.VideoCapture(path_stego_video)
    if not cap.isOpened(): print(f"  Error: Tidak bisa membuka stego-video '{path_stego_video}'."); return False
    
    frame_width_orig = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); frame_height_orig = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    processed_w, processed_h = (frame_width_orig // 8) * 8, (frame_height_orig // 8) * 8
    if processed_w == 0 or processed_h == 0: print("  Error: Dimensi video terlalu kecil."); cap.release(); return False

    all_extracted_bits_from_video = ""
    # Perkirakan jumlah bit maksimum yang bisa diekstrak dari satu frame
    max_bits_per_frame = (processed_w // 8) * (processed_h // 8) * num_ac_coeffs
    
    print("\n  [Tahap Ekstraksi 1: Membaca Bit Awal dari Video]")
    # Baca frame pertama, seharusnya cukup untuk semua metadata dan info kunci
    # Jika payload sangat besar, loop ini perlu dimodifikasi untuk membaca lebih banyak frame
    # sampai semua header (sebelum ciphertext) terbaca.
    
    # Untuk payload kita saat ini (gambar kecil), semua header + ciphertext muat di frame pertama.
    # Jadi, kita baca semua bit yang mungkin dari frame pertama.
    
    frame_num_extract = 0
    # Kita butuh setidaknya cukup bit untuk semua header sebelum panjang ciphertext
    # metadata_img (32) + len_pub_key (8) + pub_key (264) + len_salt (8) + salt (128) + 
    # len_hash (8) + hash (256) + len_nonce (8) + nonce (96) + len_tag (8) + tag (128) + len_cipher (32)
    # = 32+8+264+8+128+8+256+8+96+8+128+32 = 976 bits. Ini pasti ada di frame pertama.
    
    while True: # Loop untuk membaca frame jika payload tersebar (untuk masa depan)
        frame_num_extract += 1
        ret, frame_bgr = cap.read() 
        if not ret: 
            print(f"  Error: Video habis sebelum cukup bit diekstrak (setelah {frame_num_extract-1} frame).")
            cap.release(); return False
        
        cropped_stego_frame_bgr = frame_bgr[0:processed_h, 0:processed_w]
        print(f"    Mengekstrak bit dari frame video ke-{frame_num_extract}...")
        bits_from_current_frame = proses_frame_qim_dct(
            cropped_stego_frame_bgr, 'extract', delta_kuantisasi, 
            enable_debug_prints_extract=False, # Matikan debug detail koefisien
            num_ac_coeffs_to_use=num_ac_coeffs
        )
        if not bits_from_current_frame: 
            print(f"  Error: Tidak ada bit diekstrak dari frame ke-{frame_num_extract}.")
            # Ini bisa jadi masalah jika kita belum mendapatkan semua payload
            if len(all_extracted_bits_from_video) < 976: # Perkiraan minimal header
                 cap.release(); return False
            break # Keluar jika tidak ada bit lagi dan payload mungkin sudah cukup

        all_extracted_bits_from_video += bits_from_current_frame
        print(f"      Bit dari frame ini: {len(bits_from_current_frame)}. Total bit terkumpul: {len(all_extracted_bits_from_video)}")
        
        # Cek apakah sudah cukup untuk semua header + panjang ciphertext
        # Ini akan jadi kondisi keluar jika payload muat di beberapa frame awal
        if len(all_extracted_bits_from_video) >= 976: # Perkiraan panjang header sampai len_ciphertext
            # Setelah mendapatkan cukup bit untuk header, kita bisa parse panjang ciphertext
            # dan kemudian cek apakah sudah cukup untuk ciphertext itu sendiri.
            # Untuk sekarang, karena payload kita kecil, kita asumsikan 1 frame cukup.
            # Logika ini perlu disempurnakan untuk payload besar yang tersebar.
            break 


    current_read_idx = 0
    print("\n  [Tahap Ekstraksi 2: Parsing Metadata dan Kunci]")
    # 1. Parse Metadata Gambar Asli
    panjang_metadata_img = 2 * bits_untuk_dimensi 
    if len(all_extracted_bits_from_video) < current_read_idx + panjang_metadata_img: print_error_and_exit_extract("Bit tidak cukup untuk metadata gambar.", cap); return False
    metadata_img_bits = all_extracted_bits_from_video[current_read_idx : current_read_idx + panjang_metadata_img]; current_read_idx += panjang_metadata_img
    try:
        secret_lebar, secret_tinggi = steg_helpers.parse_metadata_bitstream(metadata_img_bits, bits_untuk_dimensi)
        print(f"    Metadata gambar diurai: Lebar={secret_lebar}, Tinggi={secret_tinggi}")
    except ValueError as e: print_error_and_exit_extract(f"Error parse metadata gambar: {e}", cap); return False
    if secret_lebar == 0 or secret_tinggi == 0: print_error_and_exit_extract("Error: Metadata gambar 0x0.", cap); return False

    # 2. Parse Kunci Publik ECC Pengirim Ephemeral
    len_pengirim_pub_ecc_bits_len = 8 
    if len(all_extracted_bits_from_video) < current_read_idx + len_pengirim_pub_ecc_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk panjang kunci publik ECC pengirim.", cap); return False
    len_pengirim_pub_ecc_bytes = bitstream_ke_int(all_extracted_bits_from_video[current_read_idx : current_read_idx + len_pengirim_pub_ecc_bits_len]); current_read_idx += len_pengirim_pub_ecc_bits_len
    pengirim_pub_ecc_bits_actual_len = len_pengirim_pub_ecc_bytes * 8
    if len(all_extracted_bits_from_video) < current_read_idx + pengirim_pub_ecc_bits_actual_len: print_error_and_exit_extract("Bit tidak cukup untuk kunci publik ECC pengirim.", cap); return False
    pengirim_pub_ecc_bits = all_extracted_bits_from_video[current_read_idx : current_read_idx + pengirim_pub_ecc_bits_actual_len]; current_read_idx += pengirim_pub_ecc_bits_actual_len
    try: pengirim_pub_ecc_bytes_extracted = bitstream_ke_bytes(pengirim_pub_ecc_bits)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi kunci publik ECC bits ke bytes: {e}", cap); return False
    print(f"    Kunci Publik ECC Pengirim ({len(pengirim_pub_ecc_bytes_extracted)} bytes) diekstrak.")
    
    # 3. Parse Salt HKDF
    len_salt_hkdf_bits_len = 8
    if len(all_extracted_bits_from_video) < current_read_idx + len_salt_hkdf_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk panjang salt HKDF.", cap); return False
    len_salt_hkdf_bytes = bitstream_ke_int(all_extracted_bits_from_video[current_read_idx : current_read_idx + len_salt_hkdf_bits_len]); current_read_idx += len_salt_hkdf_bits_len
    salt_hkdf_bits_actual_len = len_salt_hkdf_bytes * 8
    if len(all_extracted_bits_from_video) < current_read_idx + salt_hkdf_bits_actual_len: print_error_and_exit_extract("Bit tidak cukup untuk salt HKDF.", cap); return False
    salt_hkdf_bits = all_extracted_bits_from_video[current_read_idx : current_read_idx + salt_hkdf_bits_actual_len]; current_read_idx += salt_hkdf_bits_actual_len
    try: salt_hkdf_bytes_extracted = bitstream_ke_bytes(salt_hkdf_bits)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi salt HKDF bits ke bytes: {e}", cap); return False
    print(f"    Salt HKDF ({len(salt_hkdf_bytes_extracted)} bytes) diekstrak.")

    # 4. Hitung Shared Secret dan Derivasi Kunci AES
    try:
        pengirim_pub_ecc_obj_remote = deserialisasi_kunci_publik_ecc_compressed(pengirim_pub_ecc_bytes_extracted)
        shared_secret_penerima_bytes = buat_shared_secret_ecdh(kunci_privat_ecc_penerima, pengirim_pub_ecc_obj_remote)
        kunci_aes_derived_penerima = derive_kunci_aes_dari_shared_secret(shared_secret_penerima_bytes, salt_hkdf_bytes_extracted, 32)
        print("    Shared secret dan kunci AES berhasil diderivasi oleh penerima.")
    except Exception as e:
        print_error_and_exit_extract(f"Error saat ECDH atau derivasi kunci AES penerima: {e}", cap); return False

    # 5. Parse Hash SHA3-256
    len_hash_gambar_bits_len = 8 
    if len(all_extracted_bits_from_video) < current_read_idx + len_hash_gambar_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk panjang hash gambar.", cap); return False
    len_hash_gambar_bytes_extracted = bitstream_ke_int(all_extracted_bits_from_video[current_read_idx : current_read_idx + len_hash_gambar_bits_len]); current_read_idx += len_hash_gambar_bits_len
    hash_gambar_bits_actual_len = len_hash_gambar_bytes_extracted * 8
    if len(all_extracted_bits_from_video) < current_read_idx + hash_gambar_bits_actual_len: print_error_and_exit_extract("Bit tidak cukup untuk hash gambar.", cap); return False
    hash_gambar_bits_stego = all_extracted_bits_from_video[current_read_idx : current_read_idx + hash_gambar_bits_actual_len]; current_read_idx += hash_gambar_bits_actual_len
    try: hash_gambar_bytes_stego = bitstream_ke_bytes(hash_gambar_bits_stego)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi hash gambar bits ke bytes: {e}", cap); return False
    print(f"    Hash SHA3-256 gambar dari stego ({len(hash_gambar_bytes_stego)} bytes) diekstrak.")

    # 6. Parse Info AES (Nonce, Tag, Panjang Ciphertext)
    len_nonce_bits_len = 8
    if len(all_extracted_bits_from_video) < current_read_idx + len_nonce_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk panjang nonce.", cap); return False
    len_nonce_bytes = bitstream_ke_int(all_extracted_bits_from_video[current_read_idx : current_read_idx + len_nonce_bits_len]); current_read_idx += len_nonce_bits_len
    nonce_bits_len = len_nonce_bytes * 8
    if len(all_extracted_bits_from_video) < current_read_idx + nonce_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk nonce.", cap); return False
    nonce_bits = all_extracted_bits_from_video[current_read_idx : current_read_idx + nonce_bits_len]; current_read_idx += nonce_bits_len
    try: nonce_bytes_extracted = bitstream_ke_bytes(nonce_bits)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi nonce: {e}", cap); return False
    
    len_tag_bits_len = 8
    if len(all_extracted_bits_from_video) < current_read_idx + len_tag_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk panjang tag.", cap); return False
    len_tag_bytes = bitstream_ke_int(all_extracted_bits_from_video[current_read_idx : current_read_idx + len_tag_bits_len]); current_read_idx += len_tag_bits_len
    tag_bits_len = len_tag_bytes * 8
    if len(all_extracted_bits_from_video) < current_read_idx + tag_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk tag.", cap); return False
    tag_bits = all_extracted_bits_from_video[current_read_idx : current_read_idx + tag_bits_len]; current_read_idx += tag_bits_len
    try: tag_bytes_extracted = bitstream_ke_bytes(tag_bits)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi tag: {e}", cap); return False
    
    len_ciphertext_bits_len = 32
    if len(all_extracted_bits_from_video) < current_read_idx + len_ciphertext_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk panjang ciphertext.", cap); return False
    len_ciphertext_bytes = bitstream_ke_int(all_extracted_bits_from_video[current_read_idx : current_read_idx + len_ciphertext_bits_len]); current_read_idx += len_ciphertext_bits_len
    print(f"    Panjang Ciphertext diharapkan: {len_ciphertext_bytes} bytes.")

    # 7. Ekstrak Ciphertext Gambar (lanjutkan baca frame jika perlu)
    ciphertext_bits_len_needed = len_ciphertext_bytes * 8
    ciphertext_bits_collected = all_extracted_bits_from_video[current_read_idx:] 
    
    # Jika payload tersebar di banyak frame, loop ini akan berjalan
    # (Untuk gambar kecil kita, ini mungkin tidak berjalan)
    if len(ciphertext_bits_collected) < ciphertext_bits_len_needed:
        print(f"    Ciphertext belum lengkap ({len(ciphertext_bits_collected)}/{ciphertext_bits_len_needed} bits). Melanjutkan ke frame berikutnya...")
        while len(ciphertext_bits_collected) < ciphertext_bits_len_needed:
            frame_num_extract += 1; ret, frame = cap.read()
            if not ret: print(f"    Warning: Video selesai sebelum semua ciphertext diekstrak."); break
            cropped_stego_frame = frame[0:processed_h, 0:processed_w]
            print(f"    Mengekstrak sisa ciphertext dari frame {frame_num_extract}...")
            bits_from_current_frame = proses_frame_qim_dct(cropped_stego_frame, 'extract', delta_kuantisasi, num_ac_coeffs_to_use=num_ac_coeffs)
            ciphertext_bits_collected += bits_from_current_frame
            print(f"      Bit dari frame ini: {len(bits_from_current_frame)}. Total bit ciphertext terkumpul: {len(ciphertext_bits_collected)}")
    
    if len(ciphertext_bits_collected) < ciphertext_bits_len_needed: print("  Ekstraksi GAGAL: Ciphertext tidak lengkap."); cap.release(); return False
    
    final_ciphertext_bits = ciphertext_bits_collected[:ciphertext_bits_len_needed]
    try: final_ciphertext_bytes = bitstream_ke_bytes(final_ciphertext_bits)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi ciphertext: {e}", cap); return False

    print("\n  [Tahap Ekstraksi 3: Dekripsi dan Verifikasi]")
    print("    Mendekripsi gambar dengan kunci AES yang diderivasi...")
    plaintext_gambar_bytes = dekripsi_aes_gcm(final_ciphertext_bytes, kunci_aes_derived_penerima, nonce_bytes_extracted, tag_bytes_extracted)
    if plaintext_gambar_bytes is None: print("    Dekripsi GAGAL."); cap.release(); return False
    print("    Dekripsi berhasil.")

    print("    Memverifikasi hash SHA3-256 dari gambar yang didekripsi...")
    hash_gambar_dekripsi_bytes = hitung_sha3_256(plaintext_gambar_bytes)
    if hash_gambar_dekripsi_bytes == hash_gambar_bytes_stego:
        print("    Verifikasi Hash SHA3-256 BERHASIL: Gambar tidak korup.")
    else:
        print("    Verifikasi Hash SHA3-256 GAGAL: Gambar mungkin korup atau telah diubah!")
        # return False # Opsional: berhenti jika hash tidak cocok

    print("\n  [Tahap Ekstraksi 4: Rekonstruksi Gambar]")
    try: bitstream_gambar_dekripsi = bytes_ke_bitstream(plaintext_gambar_bytes)
    except Exception as e: print_error_and_exit_extract(f"Error konversi plaintext: {e}", cap); return False
    
    gambar_hasil_ekstraksi = steg_helpers.bitstream_ke_gambar(bitstream_gambar_dekripsi, secret_lebar, secret_tinggi)
    if gambar_hasil_ekstraksi:
        try: 
            gambar_hasil_ekstraksi.save(path_gambar_output)
            print(f"    Gambar (SHA3-ECC-AES) berhasil diekstrak dan disimpan sebagai '{path_gambar_output}'.")
        except Exception as e: print_error_and_exit_extract(f"Error simpan gambar: {e}", cap); return False
    else: print_error_and_exit_extract("Gagal merekonstruksi gambar.", cap); return False
    
    cap.release(); print("--- Proses Ekstraksi (SHA3-ECC-AES) Selesai ---"); return True

# --- Blok Utama untuk Menjalankan Ekstraksi ---
if __name__ == "__main__":
    print("="*70)
    print("PROSES EKSTRAKSI STEGANOGRAFI VIDEO (SHA3-ECC-AES)")
    print("="*70)

    # --- Konfigurasi Eksperimen ---
    input_dir = "media/input"
    output_dir = "media/output"
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # Path untuk stego video yang akan diekstrak
    stego_video_path = os.path.join(output_dir, "stego_video_final_output.avi") 
    path_gambar_hasil_ekstraksi_final = os.path.join(output_dir, "extracted_FINAL_secret_image.png")
    DELTA_UNTUK_TES = 20
    JUMLAH_AC_KOEFISIEN_DIPAKAI = 10
    
    print("\n--- KONFIGURASI ---")
    print(f"  Stego Video: '{stego_video_path}'")
    print(f"  Output Gambar Hasil Ekstraksi: '{path_gambar_hasil_ekstraksi_final}'")
    print(f"  DELTA QIM: {DELTA_UNTUK_TES}")
    print(f"  Koefisien AC per Blok: {JUMLAH_AC_KOEFISIEN_DIPAKAI}")
    
    # Setup kunci
    bob_private_ecc, _ = setup_kunci_ecc()
    
    if bob_private_ecc and os.path.exists(stego_video_path):
        # Proses Ekstraksi
        print("\n--- MEMULAI PROSES EKSTRAKSI DARI FILE VIDEO ---")
        berhasil_ekstrak_final = ekstraksi_gambar_video_final(
            stego_video_path, 
            path_gambar_hasil_ekstraksi_final, 
            DELTA_UNTUK_TES,
            JUMLAH_AC_KOEFISIEN_DIPAKAI,
            bob_private_ecc 
        )
        
        print("\n--- HASIL EKSTRAKSI ---")
        if berhasil_ekstrak_final:
            print(f"  Status: VERIFIKASI EKSTRAKSI (SHA3-ECC-AES) DARI FILE BERHASIL!")
            print(f"  Gambar Rahasia Diekstrak ke: '{path_gambar_hasil_ekstraksi_final}'")
            
            # Cek gambar hasil ekstraksi jika ada gambar asli untuk dibandingkan
            gambar_rahasia_path = os.path.join(input_dir, "ini_adalah_rahasia_grayscale.png")
            if os.path.exists(gambar_rahasia_path) and os.path.exists(path_gambar_hasil_ekstraksi_final):
                try:
                    img_asli = Image.open(gambar_rahasia_path).convert('L') 
                    img_ekstrak = Image.open(path_gambar_hasil_ekstraksi_final).convert('L')
                    if np.array_equal(np.array(img_asli), np.array(img_ekstrak)):
                        print("  Pengecekan Piksel: Gambar asli dan hasil ekstraksi IDENTIK.")
                    else:
                        print("  Pengecekan Piksel: Gambar asli dan hasil ekstraksi BERBEDA.")
                except Exception as e_compare:
                    print(f"  Error saat membandingkan gambar: {e_compare}")
        else:
            print("  Status: VERIFIKASI EKSTRAKSI (SHA3-ECC-AES) DARI FILE GAGAL.")
    else:
        print("\n# filepath: d:\Project\kripto\Secure-Video-Steganography-using-ECC-and-DCT\extract_process.py")