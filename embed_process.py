import os
import cv2
import numpy as np
from PIL import Image
import helpers as steg_helpers

# Import fungsi-fungsi dari config_and_setup
from config_and_setup import (
    bytes_ke_bitstream, bitstream_ke_bytes, int_ke_bitstream, 
    enkripsi_aes_gcm, buat_pasangan_kunci_ecc, serialisasi_kunci_publik_ecc_compressed, 
    deserialisasi_kunci_publik_ecc_compressed, buat_shared_secret_ecdh, 
    derive_kunci_aes_dari_shared_secret, hitung_sha3_256, proses_frame_qim_dct,
    setup_kunci_ecc, persiapkan_file_input
)

# --- Fungsi Embed Utama (Grayscale, SHA3, ECC-AES) ---
def embed_gambar_ke_video_final(path_video_input, path_gambar_rahasia, path_video_output_base, 
                                delta_kuantisasi, num_ac_coeffs, 
                                kunci_publik_ecc_penerima_bytes_compressed):
    print(f"\n=== MEMULAI PROSES EMBEDDING GAMBAR KE VIDEO ===")
    print(f"  Gambar Rahasia: '{path_gambar_rahasia}'")
    print(f"  Video Input: '{path_video_input}'")
    print(f"  Parameter: DELTA={delta_kuantisasi}, Koefisien AC per Blok={num_ac_coeffs}")
    
    secret_lebar, secret_tinggi, bitstream_gambar_asli = steg_helpers.gambar_ke_bitstream(path_gambar_rahasia)
    if bitstream_gambar_asli is None: return False, None, None
    try: bytes_gambar_asli = bitstream_ke_bytes(bitstream_gambar_asli)
    except ValueError as e: print(f"  Error: Konversi bitstream gambar ke bytes gagal: {e}"); return False, None, None

    print("\n  [Tahap Embedding 1: Persiapan Kriptografi]")
    print("    Menghitung hash SHA3-256 dari gambar asli...")
    hash_gambar_asli_bytes = hitung_sha3_256(bytes_gambar_asli)
    bitstream_hash_gambar = bytes_ke_bitstream(hash_gambar_asli_bytes)
    print(f"      Hash SHA3-256 ({len(hash_gambar_asli_bytes)} bytes) dibuat.")

    print("    Setup ECC untuk pengirim dan menghitung shared secret...")
    try:
        pengirim_priv_ecc_eph, pengirim_pub_ecc_eph = buat_pasangan_kunci_ecc()
        kunci_publik_ecc_penerima = deserialisasi_kunci_publik_ecc_compressed(kunci_publik_ecc_penerima_bytes_compressed)
        shared_secret_bytes = buat_shared_secret_ecdh(pengirim_priv_ecc_eph, kunci_publik_ecc_penerima)
        salt_untuk_hkdf = os.urandom(16) 
        kunci_aes_derived = derive_kunci_aes_dari_shared_secret(shared_secret_bytes, salt_untuk_hkdf, 32)
        bytes_pengirim_pub_ecc_eph = serialisasi_kunci_publik_ecc_compressed(pengirim_pub_ecc_eph)
        bitstream_pengirim_pub_ecc_eph = bytes_ke_bitstream(bytes_pengirim_pub_ecc_eph)
        bitstream_salt_hkdf = bytes_ke_bitstream(salt_untuk_hkdf)
        print("      Kunci AES berhasil diderivasi dari shared secret ECC.")
    except Exception as e:
        print(f"    Error: Setup ECC atau derivasi kunci AES gagal: {e}"); return False, None, None
    
    print("    Mengenkripsi gambar rahasia dengan kunci AES yang diderivasi...")
    try:
        ciphertext_bytes, nonce_bytes, tag_bytes = enkripsi_aes_gcm(bytes_gambar_asli, kunci_aes_derived)
        print("      Gambar berhasil dienkripsi.")
    except Exception as e:
        print(f"    Error: Enkripsi AES gagal: {e}"); return False, None, None
    bitstream_ciphertext = bytes_ke_bitstream(ciphertext_bytes)
    bitstream_nonce = bytes_ke_bitstream(nonce_bytes)
    bitstream_tag = bytes_ke_bitstream(tag_bytes)

    print("\n  [Tahap Embedding 2: Membuat Payload Lengkap]")
    try:
        metadata_img_bits = steg_helpers.buat_metadata_bitstream(secret_lebar, secret_tinggi)
        len_pengirim_pub_ecc_bits_val = int_ke_bitstream(len(bytes_pengirim_pub_ecc_eph), 8)
        len_salt_hkdf_bits_val = int_ke_bitstream(len(salt_untuk_hkdf), 8)
        len_hash_gambar_bits_val = int_ke_bitstream(len(hash_gambar_asli_bytes), 8)
        len_nonce_bits_val = int_ke_bitstream(len(nonce_bytes), 8)
        len_tag_bits_val = int_ke_bitstream(len(tag_bytes), 8)
        len_ciphertext_bits_val = int_ke_bitstream(len(ciphertext_bytes), 32)
        total_payload_bitstream = ( metadata_img_bits + len_pengirim_pub_ecc_bits_val + 
                                    bitstream_pengirim_pub_ecc_eph + len_salt_hkdf_bits_val + 
                                    bitstream_salt_hkdf + len_hash_gambar_bits_val + 
                                    bitstream_hash_gambar + len_nonce_bits_val + 
                                    bitstream_nonce + len_tag_bits_val + bitstream_tag + 
                                    len_ciphertext_bits_val + bitstream_ciphertext )
        print(f"    Total bit payload yang akan disisipkan: {len(total_payload_bitstream)} bits.")
        print(f"      - Metadata Gambar: {len(metadata_img_bits)} bits (L:{secret_lebar}, T:{secret_tinggi})")
        print(f"      - Info Kunci Publik ECC Pengirim: {8 + len(bitstream_pengirim_pub_ecc_eph)} bits")
        print(f"      - Info Salt HKDF: {8 + len(bitstream_salt_hkdf)} bits")
        print(f"      - Info Hash SHA3: {8 + len(bitstream_hash_gambar)} bits")
        print(f"      - Info Nonce AES: {8 + len(bitstream_nonce)} bits")
        print(f"      - Info Tag AES: {8 + len(bitstream_tag)} bits")
        print(f"      - Info Ciphertext: {32 + len(bitstream_ciphertext)} bits")
    except ValueError as e:
        print(f"    Error: Gagal membuat payload: {e}"); return False, None, None
    
    total_bits_to_embed = len(total_payload_bitstream)
    
    print("\n  [Tahap Embedding 3: Menyisipkan Payload ke Frame Video]")
    cap = cv2.VideoCapture(path_video_input)
    if not cap.isOpened(): print(f"    Error: Video input '{path_video_input}' tidak bisa dibuka."); return False, None, None
    
    frame_width_orig = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); frame_height_orig = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    output_w, output_h = (frame_width_orig // 8) * 8, (frame_height_orig // 8) * 8
    if output_w == 0 or output_h == 0: print("    Error: Dimensi video terlalu kecil."); cap.release(); return False, None, None
    
    base_name_output, _ = os.path.splitext(path_video_output_base)
    actual_video_output_path = base_name_output + ".avi"
    fourcc = cv2.VideoWriter_fourcc(*'F', 'F', 'V', '1') 
    out = cv2.VideoWriter(actual_video_output_path, fourcc, fps, (output_w, output_h), isColor=True) 
    if not out.isOpened(): print(f"    ERROR: Gagal VideoWriter FFV1 '{actual_video_output_path}'."); cap.release(); return False, None, None
    
    print(f"    Video output akan disimpan sebagai '{actual_video_output_path}' (Codec: FFV1).")
    current_payload_bit_index = 0; frame_num = 0; embedded_all_payload = False
    first_stego_frame_gray_for_psnr = None 
    first_original_gray_for_psnr = None

    while True:
        ret, frame_bgr = cap.read()
        if not ret:
            if not embedded_all_payload: print(f"    Warning: Video selesai sebelum semua payload ({total_bits_to_embed} bits) disisipkan.")
            break
        frame_num += 1; cropped_frame_bgr = frame_bgr[0:output_h, 0:output_w]
        
        if current_payload_bit_index < total_bits_to_embed:
            bits_to_embed_in_this_frame_segment = total_payload_bitstream[current_payload_bit_index:]
            original_gray_ref_uint8, stego_frame_gray_output, bits_embedded_this_frame = proses_frame_qim_dct(
                cropped_frame_bgr, 'embed', delta_kuantisasi, 
                bits_to_embed_in_this_frame_segment, 
                num_ac_coeffs_to_use=num_ac_coeffs
            )
            if frame_num == 1: 
                first_original_gray_for_psnr = original_gray_ref_uint8.copy()
                first_stego_frame_gray_for_psnr = stego_frame_gray_output.copy()
            
            stego_frame_bgr_to_write = cv2.cvtColor(stego_frame_gray_output, cv2.COLOR_GRAY2BGR)
            out.write(stego_frame_bgr_to_write)
            current_payload_bit_index += bits_embedded_this_frame
            print(f"    Frame {frame_num}: {bits_embedded_this_frame} bits disisipkan. Total disisipkan: {current_payload_bit_index}/{total_bits_to_embed}")
            
            if current_payload_bit_index >= total_bits_to_embed:
                embedded_all_payload = True; print("    Semua payload (SHA3-ECC-AES) berhasil disisipkan!")
                # Salin sisa frame asli jika payload sudah selesai sebelum video habis
                while True: 
                    ret_sisa, frame_sisa_bgr = cap.read()
                    if not ret_sisa: break
                    frame_num +=1
                    cropped_frame_sisa_bgr = frame_sisa_bgr[0:output_h, 0:output_w]
                    out.write(cropped_frame_sisa_bgr) 
                break 
        else: # Seharusnya tidak pernah sampai sini jika logika di atas benar
            if len(cropped_frame_bgr.shape) == 2: cropped_frame_bgr_to_write = cv2.cvtColor(cropped_frame_bgr, cv2.COLOR_GRAY2BGR)
            else: cropped_frame_bgr_to_write = cropped_frame_bgr
            out.write(cropped_frame_bgr_to_write)
            
    cap.release(); out.release()
    if embedded_all_payload: 
        print(f"  Proses embedding (SHA3-ECC-AES) selesai. Video output: '{actual_video_output_path}'.")
        return True, first_original_gray_for_psnr, first_stego_frame_gray_for_psnr
    else: 
        print(f"  Proses embedding (SHA3-ECC-AES) selesai, namun TIDAK semua data berhasil disisipkan."); 
        return False, None, None

# --- Blok Utama untuk Menjalankan Embedding ---
if __name__ == "__main__":
    print("="*70)
    print("PROSES EMBEDDING STEGANOGRAFI VIDEO (SHA3-ECC-AES)")
    print("="*70)

    # --- Konfigurasi Eksperimen ---
    input_dir = "media/input"
    output_dir = "media/output"
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    video_input_path = os.path.join(input_dir, "cover.mp4")
    gambar_rahasia_path = os.path.join(input_dir, "ini_adalah_rahasia_grayscale.png") # Gambar grayscale
    video_output_stego_base_path = os.path.join(output_dir, "stego_video_final_output")
    DELTA_UNTUK_TES = 20 
    JUMLAH_AC_KOEFISIEN_DIPAKAI = 10
    
    print("\n--- KONFIGURASI ---")
    print(f"  Video Input: '{video_input_path}'")
    print(f"  Gambar Rahasia: '{gambar_rahasia_path}'")
    print(f"  Output Stego Video (base): '{video_output_stego_base_path}.avi'")
    print(f"  DELTA QIM: {DELTA_UNTUK_TES}")
    print(f"  Koefisien AC per Blok: {JUMLAH_AC_KOEFISIEN_DIPAKAI}")
    
    # Persiapkan file input
    file_siap = persiapkan_file_input(input_dir, video_input_path, gambar_rahasia_path)
    
    # Setup kunci
    bob_private_ecc, bob_public_key_bytes_compressed = setup_kunci_ecc()
    
    if bob_private_ecc and bob_public_key_bytes_compressed and file_siap:
        # Proses Embedding
        stego_video_file_path_final = video_output_stego_base_path 
        
        berhasil_embed_final, first_orig_gray, first_stego_gray = embed_gambar_ke_video_final(
            video_input_path, 
            gambar_rahasia_path, 
            stego_video_file_path_final, 
            DELTA_UNTUK_TES,
            JUMLAH_AC_KOEFISIEN_DIPAKAI,
            bob_public_key_bytes_compressed 
        )

        if berhasil_embed_final:
            actual_stego_avi_path_final = steg_helpers.get_avi_path(stego_video_file_path_final) 
            print("\n--- HASIL EMBEDDING ---")
            print(f"  Status: EMBEDDING GAMBAR (SHA3-ECC-AES) KE FILE VIDEO SELESAI DENGAN SUKSES.")
            print(f"  Video Output: '{actual_stego_avi_path_final}'")

            if first_orig_gray is not None and first_stego_gray is not None:
                psnr_val = cv2.PSNR(first_orig_gray, first_stego_gray)
                print(f"  PSNR Frame Pertama (Asli Grayscale vs Stego Grayscale): {psnr_val:.2f} dB")
        else:
            print("\n--- HASIL EMBEDDING ---")
            print("  Status: EMBEDDING GAMBAR (SHA3-ECC-AES) KE FILE VIDEO GAGAL.")
    else:
        print("\nProses tidak bisa dimulai karena file input (video/gambar rahasia) atau kunci ECC tidak tersedia.")
        if not file_siap:
            if not os.path.exists(video_input_path): print(f"  - Video '{video_input_path}' tidak ditemukan.")
            if not os.path.exists(gambar_rahasia_path): print(f"  - Gambar '{gambar_rahasia_path}' tidak ditemukan.")
    
    print("\nPROGRAM SELESAI")
    print("="*70)