import cv2
import numpy as np
from scipy.fftpack import dct, idct
import os
from PIL import Image
import helpers as steg_helpers

# Impor untuk AES dan ECC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# --- Konfigurasi Global ---
_g_debug_print_count = 0
_MAX_DEBUG_PRINTS_PER_CALL = 64
block_size = 8  # Define block size as a global constant

# KUNCI_AES_256 tidak dipakai lagi, akan diderivasi dari ECC
# KUNCI_AES_256 = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'

# --- Fungsi Helper Bytes <-> Bitstream dan Int <-> Bitstream (SAMA SEPERTI SEBELUMNYA) ---
def bytes_ke_bitstream(data_bytes):
    return ''.join(format(byte, '08b') for byte in data_bytes)

def bitstream_ke_bytes(bitstream_data):
    if len(bitstream_data) % 8 != 0:
        raise ValueError("Panjang bitstream bukan kelipatan 8.")
    return bytes(int(bitstream_data[i:i+8], 2) for i in range(0, len(bitstream_data), 8))

def int_ke_bitstream(nilai_int, jumlah_bit):
    if nilai_int < 0 or nilai_int >= (2**jumlah_bit):
        raise ValueError(f"Nilai {nilai_int} di luar jangkauan untuk {jumlah_bit} bit.")
    return format(nilai_int, f'0{jumlah_bit}b')

def bitstream_ke_int(bitstream_nilai, jumlah_bit_diharapkan=None):
    if jumlah_bit_diharapkan and len(bitstream_nilai) != jumlah_bit_diharapkan:
        raise ValueError(f"Panjang bitstream {len(bitstream_nilai)} tidak sesuai dengan {jumlah_bit_diharapkan} bit yang diharapkan.")
    return int(bitstream_nilai, 2)

# --- Fungsi Enkripsi dan Dekripsi AES-GCM (SAMA SEPERTI SEBELUMNYA) ---
def enkripsi_aes_gcm(data_bytes, kunci_aes_derived):
    if len(kunci_aes_derived) not in (16, 24, 32): 
        raise ValueError("Kunci AES harus 16, 24, atau 32 byte.")
    aesgcm = AESGCM(kunci_aes_derived)
    nonce = os.urandom(12) 
    ciphertext_with_tag = aesgcm.encrypt(nonce, data_bytes, None)
    tag_length = 16 
    actual_ciphertext = ciphertext_with_tag[:-tag_length]
    tag = ciphertext_with_tag[-tag_length:]
    return actual_ciphertext, nonce, tag

def dekripsi_aes_gcm(ciphertext_bytes, kunci_aes_derived, nonce_bytes, tag_bytes):
    if len(kunci_aes_derived) not in (16, 24, 32):
        raise ValueError("Kunci AES harus 16, 24, atau 32 byte.")
    try:
        aesgcm = AESGCM(kunci_aes_derived)
        ciphertext_with_tag = ciphertext_bytes + tag_bytes
        plaintext_bytes = aesgcm.decrypt(nonce_bytes, ciphertext_with_tag, None)
        return plaintext_bytes
    except InvalidTag:
        print("Error Dekripsi AES: Tag autentikasi tidak valid. Data mungkin korup atau kunci salah.")
        return None
    except Exception as e:
        print(f"Error Dekripsi AES lainnya: {e}")
        return None

# --- Fungsi Helper ECC / ECDH ---
def buat_pasangan_kunci_ecc():
    """Membuat pasangan kunci privat dan publik ECC (SECP256R1)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialisasi_kunci_publik_ecc_compressed(public_key_ecc):
    """Mengubah objek kunci publik ECC ke format bytes terkompresi."""
    return public_key_ecc.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

def deserialisasi_kunci_publik_ecc_compressed(public_key_bytes_compressed, kurva=ec.SECP256R1()):
    """Mengubah bytes terkompresi kembali ke objek kunci publik ECC."""
    return ec.EllipticCurvePublicKey.from_encoded_point(kurva, public_key_bytes_compressed)

def buat_shared_secret_ecdh(private_key_lokal_ecc, public_key_remote_ecc):
    """Melakukan ECDH exchange untuk menghasilkan shared secret."""
    shared_secret = private_key_lokal_ecc.exchange(ec.ECDH(), public_key_remote_ecc)
    return shared_secret

def derive_kunci_aes_dari_shared_secret(shared_secret_bytes, salt_bytes=None, panjang_kunci_aes_bytes=32):
    """Menderivasi kunci AES dari shared secret menggunakan HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=panjang_kunci_aes_bytes, 
        salt=salt_bytes,
        info=b'kunci aes untuk steganografi video', 
    )
    derived_key = hkdf.derive(shared_secret_bytes)
    return derived_key

def proses_frame_qim_dct(frame_input, mode, delta, 
                         bit_payload_segment=None, 
                         enable_debug_prints_extract=False,
                         num_ac_coeffs_to_use=63):
    global _g_debug_print_count 
    if len(frame_input.shape) == 3 and frame_input.shape[2] == 3: 
        gray_frame_reference_uint8 = cv2.cvtColor(frame_input, cv2.COLOR_BGR2GRAY)
    elif len(frame_input.shape) == 2: 
        gray_frame_reference_uint8 = frame_input.copy()
    else:
        raise ValueError("Format frame input tidak didukung.")
    img_to_process_float = np.float32(gray_frame_reference_uint8) 
    height, width = img_to_process_float.shape
    output_pixel_data_float = img_to_process_float.copy() 
    extracted_bits_list = [] 
    current_payload_bit_idx = 0 
    bits_processed_in_this_frame = 0 
    max_bits_to_embed_from_segment = 0
    if mode == 'embed' and bit_payload_segment:
        max_bits_to_embed_from_segment = len(bit_payload_segment)
    stop_processing_current_payload_segment = False
    if mode == 'extract' and enable_debug_prints_extract:
        _g_debug_print_count = 0 
    for r_start in range(0, height, block_size):
        if mode == 'embed' and current_payload_bit_idx >= max_bits_to_embed_from_segment: break 
        for c_start in range(0, width, block_size):
            if mode == 'embed' and current_payload_bit_idx >= max_bits_to_embed_from_segment: break
            r_end = r_start + block_size; c_end = c_start + block_size
            current_block_to_transform = img_to_process_float[r_start:r_end, c_start:c_end]
            dct_block = dct(dct(current_block_to_transform, axis=0, norm='ortho'), axis=1, norm='ortho')
            flat_dct_coeffs = dct_block.flatten()
            modified_flat_coeffs = flat_dct_coeffs.copy() 
            coeffs_this_block_can_process = min(num_ac_coeffs_to_use, len(flat_dct_coeffs) - 1)
            for i_ac_idx in range(coeffs_this_block_can_process):
                coeff_array_idx = i_ac_idx + 1
                if mode == 'embed' and current_payload_bit_idx >= max_bits_to_embed_from_segment: break 
                coeff_val_to_process = flat_dct_coeffs[coeff_array_idx] 
                if delta <= 0: 
                    if mode == 'extract': extracted_bits_list.append('0'); bits_processed_in_this_frame +=1
                    continue
                if mode == 'embed':
                    bit_to_embed = int(bit_payload_segment[current_payload_bit_idx])
                    quantized_index_from_original = int(round(coeff_val_to_process / delta))
                    final_quantized_index = quantized_index_from_original
                    current_parity = final_quantized_index % 2
                    if current_parity != bit_to_embed:
                        if bit_to_embed == 1: 
                            if final_quantized_index % 2 == 0: final_quantized_index += 1 
                        else: 
                            if final_quantized_index % 2 != 0: final_quantized_index -=1 
                    modified_flat_coeffs[coeff_array_idx] = float(final_quantized_index * delta)
                    current_payload_bit_idx += 1
                    bits_processed_in_this_frame +=1
                elif mode == 'extract':
                    quantized_index = int(round(coeff_val_to_process / delta)) 
                    extracted_bit = int(quantized_index % 2)
                    extracted_bits_list.append(str(extracted_bit))
                    bits_processed_in_this_frame +=1
                    if enable_debug_prints_extract and _g_debug_print_count < _MAX_DEBUG_PRINTS_PER_CALL:
                        # print(f"DEBUG EXTRACT (Blok {r_start//8},{c_start//8}, CoeffAC {i_ac_idx}, BitFrameKe-{bits_processed_in_this_frame}):")
                        # print(f"  delta: {delta}")
                        # print(f"  stego_coeff_val: {coeff_val_to_process:.4f}")
                        # print(f"  coeff/delta: {(coeff_val_to_process / delta):.4f}")
                        # print(f"  round(coeff/delta): {round(coeff_val_to_process / delta)}")
                        # print(f"  quantized_index (int): {quantized_index}")
                        # print(f"  extracted_bit: {extracted_bit}")
                        _g_debug_print_count += 1
            if mode == 'embed':
                dct_block_to_idct = modified_flat_coeffs.reshape((block_size, block_size))
                idct_block = idct(idct(dct_block_to_idct, axis=0, norm='ortho'), axis=1, norm='ortho')
                output_pixel_data_float[r_start:r_end, c_start:c_end] = idct_block
    if mode == 'embed':
        stego_frame_uint8 = np.uint8(np.clip(output_pixel_data_float, 0, 255))
        return gray_frame_reference_uint8, stego_frame_uint8, current_payload_bit_idx 
    elif mode == 'extract':
        return "".join(extracted_bits_list)

# --- Fungsi Embed Utama (Dimodifikasi untuk ECC-AES) ---
def embed_gambar_ke_video_ecc_aes(path_video_input, path_gambar_rahasia, path_video_output_base, 
                                  delta_kuantisasi, num_ac_coeffs, 
                                  kunci_publik_ecc_penerima_bytes_compressed): 
    print(f"Memulai EMBEDDING (ECC-AES) gambar '{path_gambar_rahasia}' ke video '{path_video_input}'...")
    
    secret_lebar, secret_tinggi, bitstream_gambar_asli = steg_helpers.gambar_ke_bitstream(path_gambar_rahasia)
    if bitstream_gambar_asli is None: return False, None
    try: bytes_gambar_asli = bitstream_ke_bytes(bitstream_gambar_asli)
    except ValueError as e: print(f"Error konversi bitstream gambar ke bytes: {e}"); return False, None

    print("Setup ECC dan membuat shared secret...")
    try:
        pengirim_priv_ecc_eph, pengirim_pub_ecc_eph = buat_pasangan_kunci_ecc()
        kunci_publik_ecc_penerima = deserialisasi_kunci_publik_ecc_compressed(kunci_publik_ecc_penerima_bytes_compressed)
        shared_secret_bytes = buat_shared_secret_ecdh(pengirim_priv_ecc_eph, kunci_publik_ecc_penerima)
        salt_untuk_hkdf = os.urandom(16) 
        kunci_aes_derived = derive_kunci_aes_dari_shared_secret(shared_secret_bytes, salt_untuk_hkdf, 32)
        bitstream_pengirim_pub_ecc_eph = bytes_ke_bitstream(serialisasi_kunci_publik_ecc_compressed(pengirim_pub_ecc_eph))
        bitstream_salt_hkdf = bytes_ke_bitstream(salt_untuk_hkdf)
    except Exception as e:
        print(f"Error saat setup ECC atau derivasi kunci AES: {e}"); return False, None

    print("Mengenkripsi gambar rahasia dengan kunci AES yang diderivasi...")
    try:
        ciphertext_bytes, nonce_bytes, tag_bytes = enkripsi_aes_gcm(bytes_gambar_asli, kunci_aes_derived)
    except Exception as e:
        print(f"Error saat enkripsi AES: {e}"); return False, None
    
    bitstream_ciphertext = bytes_ke_bitstream(ciphertext_bytes)
    bitstream_nonce = bytes_ke_bitstream(nonce_bytes)
    bitstream_tag = bytes_ke_bitstream(tag_bytes)

    try:
        metadata_img_bits = steg_helpers.buat_metadata_bitstream(secret_lebar, secret_tinggi)
        len_pengirim_pub_ecc_bytes = len(serialisasi_kunci_publik_ecc_compressed(pengirim_pub_ecc_eph))
        len_pengirim_pub_ecc_bits_val = int_ke_bitstream(len_pengirim_pub_ecc_bytes, 8)
        len_salt_hkdf_bytes = len(salt_untuk_hkdf)
        len_salt_hkdf_bits_val = int_ke_bitstream(len_salt_hkdf_bytes, 8)
        len_nonce_bits_val = int_ke_bitstream(len(nonce_bytes), 8)
        len_tag_bits_val = int_ke_bitstream(len(tag_bytes), 8)
        len_ciphertext_bits_val = int_ke_bitstream(len(ciphertext_bytes), 32)
        total_payload_bitstream = ( metadata_img_bits + len_pengirim_pub_ecc_bits_val + bitstream_pengirim_pub_ecc_eph + 
                                    len_salt_hkdf_bits_val + bitstream_salt_hkdf + len_nonce_bits_val + 
                                    bitstream_nonce + len_tag_bits_val + bitstream_tag + 
                                    len_ciphertext_bits_val + bitstream_ciphertext )
        # print(f"DEBUG: Panjang Kunci Publik ECC Ephemeral: {len_pengirim_pub_ecc_bytes} bytes ({len(bitstream_pengirim_pub_ecc_eph)} bits)")
        # print(f"DEBUG: Panjang Salt HKDF: {len_salt_hkdf_bytes} bytes ({len(bitstream_salt_hkdf)} bits)")
    except ValueError as e:
        print(f"Error membuat payload: {e}"); return False, None

    total_bits_to_embed = len(total_payload_bitstream)
    print(f"Total bit payload (ECC-AES) yang akan disisipkan: {total_bits_to_embed} bits.")
    
    cap = cv2.VideoCapture(path_video_input)
    if not cap.isOpened(): print(f"Error: Video input '{path_video_input}' tidak bisa dibuka."); return False, None
    frame_width_orig = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); frame_height_orig = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    output_w, output_h = (frame_width_orig // 8) * 8, (frame_height_orig // 8) * 8
    if output_w == 0 or output_h == 0: print("Error: Dimensi video terlalu kecil."); cap.release(); return False, None
    
    base_name_output, _ = os.path.splitext(path_video_output_base)
    actual_video_output_path = base_name_output + ".avi"
    
    fourcc = cv2.VideoWriter_fourcc(*'F', 'F', 'V', '1') 
    out = cv2.VideoWriter(actual_video_output_path, fourcc, fps, (output_w, output_h))
    if not out.isOpened(): print(f"ERROR: Gagal VideoWriter FFV1 '{actual_video_output_path}'."); cap.release(); return False, None
    
    print(f"Video output akan disimpan sebagai '{actual_video_output_path}' (Codec: FFV1).")
    current_payload_bit_index = 0; frame_num = 0; embedded_all_payload = False
    first_stego_frame_for_psnr = None # Untuk menyimpan frame stego pertama

    while True:
        ret, frame = cap.read()
        if not ret:
            if not embedded_all_payload: print(f"\nWarning: Video selesai sebelum semua payload ({total_bits_to_embed} bits) disisipkan.")
            break
        frame_num += 1; cropped_frame = frame[0:output_h, 0:output_w]
        
        original_gray_for_psnr_calc, stego_frame_gray, bits_embedded_this_frame = proses_frame_qim_dct(
            cropped_frame, 'embed', delta_kuantisasi, 
            total_payload_bitstream[current_payload_bit_index:], # Kirim sisa payload
            num_ac_coeffs_to_use=num_ac_coeffs
        )
        
        if frame_num == 1: # Simpan frame stego pertama untuk perhitungan PSNR nanti
            first_stego_frame_for_psnr = stego_frame_gray.copy()
            
        stego_frame_bgr = cv2.cvtColor(stego_frame_gray, cv2.COLOR_GRAY2BGR)
        out.write(stego_frame_bgr)
        current_payload_bit_index += bits_embedded_this_frame
        
        print(f"Frame {frame_num}: {bits_embedded_this_frame} bits disisipkan. Total: {current_payload_bit_index}/{total_bits_to_embed}")
        if current_payload_bit_index >= total_bits_to_embed:
            embedded_all_payload = True; print("\nSemua payload (ECC-AES) berhasil disisipkan!")
            # Salin sisa frame asli jika payload sudah selesai sebelum video habis
            while True:
                ret_sisa, frame_sisa = cap.read()
                if not ret_sisa: break
                frame_num +=1
                cropped_frame_sisa = frame_sisa[0:output_h, 0:output_w]
                if len(cropped_frame_sisa.shape) == 2: cropped_frame_sisa_bgr = cv2.cvtColor(cropped_frame_sisa, cv2.COLOR_GRAY2BGR)
                else: cropped_frame_sisa_bgr = cropped_frame_sisa
                out.write(cropped_frame_sisa_bgr)
                # print(f"Frame {frame_num}: Menyalin frame asli.")
            break # Keluar dari loop utama while
            
    cap.release(); out.release()
    if embedded_all_payload: 
        print(f"Proses embedding (ECC-AES) selesai. Video output: '{actual_video_output_path}'.")
        return True, first_stego_frame_for_psnr # Kembalikan juga frame stego pertama
    else: 
        print(f"Proses embedding (ECC-AES) selesai, TIDAK semua data disisipkan.")
        return False, None


# --- Fungsi Ekstraksi Utama (Dimodifikasi untuk ECC-AES) --- 
def ekstraksi_gambar_video_ecc_aes(path_stego_video, path_gambar_output, 
                                   delta_kuantisasi, num_ac_coeffs, 
                                   kunci_privat_ecc_penerima, 
                                   bits_untuk_dimensi=16):
    print(f"Memulai EKSTRAKSI (ECC-AES) gambar dari video '{path_stego_video}'...")
    cap = cv2.VideoCapture(path_stego_video)
    if not cap.isOpened(): print(f"Error: Tidak bisa membuka stego-video '{path_stego_video}'."); return False
    
    frame_width_orig = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); frame_height_orig = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    processed_w, processed_h = (frame_width_orig // 8) * 8, (frame_height_orig // 8) * 8
    if processed_w == 0 or processed_h == 0: print("Error: Dimensi video terlalu kecil."); cap.release(); return False

    all_extracted_bits_from_video = ""
    # Ekstrak dari frame pertama untuk metadata dan awal data
    ret, frame = cap.read()
    if not ret: print("Error: Tidak bisa membaca frame dari stego-video."); cap.release(); return False
    cropped_stego_frame = frame[0:processed_h, 0:processed_w]
    
    print("Mengekstrak bit dari frame pertama...")
    bits_from_current_frame = proses_frame_qim_dct(
        cropped_stego_frame, 'extract', delta_kuantisasi, 
        enable_debug_prints_extract=False, 
        num_ac_coeffs_to_use=num_ac_coeffs
    )
    if not bits_from_current_frame: print("Error: Tidak ada bit diekstrak dari frame pertama."); cap.release(); return False
    all_extracted_bits_from_video += bits_from_current_frame
    print(f"Total bit diekstrak dari frame pertama: {len(bits_from_current_frame)} bits.")

    current_read_idx = 0
    # 1. Parse Metadata Gambar Asli
    panjang_metadata_img = 2 * bits_untuk_dimensi 
    if len(all_extracted_bits_from_video) < current_read_idx + panjang_metadata_img: print_error_and_exit_extract("Bit tidak cukup untuk metadata gambar.", cap); return False
    metadata_img_bits = all_extracted_bits_from_video[current_read_idx : current_read_idx + panjang_metadata_img]; current_read_idx += panjang_metadata_img
    try:
        secret_lebar, secret_tinggi = steg_helpers.parse_metadata_bitstream(metadata_img_bits, bits_untuk_dimensi)
        print(f"Metadata gambar diurai: Lebar={secret_lebar}, Tinggi={secret_tinggi}")
    except ValueError as e: print_error_and_exit_extract(f"Error parse metadata gambar: {e}", cap); return False
    if secret_lebar == 0 or secret_tinggi == 0: print_error_and_exit_extract("Error: Metadata gambar 0x0.", cap); return False

    # 2. Parse Kunci Publik ECC Pengirim Ephemeral
    len_pengirim_pub_ecc_bits_len = 8
    if len(all_extracted_bits_from_video) < current_read_idx + len_pengirim_pub_ecc_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk panjang kunci publik ECC pengirim.", cap); return False
    len_pengirim_pub_ecc_bytes = bitstream_ke_int(all_extracted_bits_from_video[current_read_idx : current_read_idx + len_pengirim_pub_ecc_bits_len]); current_read_idx += len_pengirim_pub_ecc_bits_len
    print(f"Panjang Kunci Publik ECC Pengirim diharapkan: {len_pengirim_pub_ecc_bytes} bytes.")
    
    pengirim_pub_ecc_bits_actual_len = len_pengirim_pub_ecc_bytes * 8
    if len(all_extracted_bits_from_video) < current_read_idx + pengirim_pub_ecc_bits_actual_len: print_error_and_exit_extract("Bit tidak cukup untuk kunci publik ECC pengirim.", cap); return False
    pengirim_pub_ecc_bits = all_extracted_bits_from_video[current_read_idx : current_read_idx + pengirim_pub_ecc_bits_actual_len]; current_read_idx += pengirim_pub_ecc_bits_actual_len
    try: pengirim_pub_ecc_bytes_extracted = bitstream_ke_bytes(pengirim_pub_ecc_bits)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi kunci publik ECC bits ke bytes: {e}", cap); return False
    print(f"Kunci Publik ECC Pengirim diekstrak ({len(pengirim_pub_ecc_bytes_extracted)} bytes).")

    # 3. Parse Salt HKDF
    len_salt_hkdf_bits_len = 8
    if len(all_extracted_bits_from_video) < current_read_idx + len_salt_hkdf_bits_len: print_error_and_exit_extract("Bit tidak cukup untuk panjang salt HKDF.", cap); return False
    len_salt_hkdf_bytes = bitstream_ke_int(all_extracted_bits_from_video[current_read_idx : current_read_idx + len_salt_hkdf_bits_len]); current_read_idx += len_salt_hkdf_bits_len
    print(f"Panjang Salt HKDF diharapkan: {len_salt_hkdf_bytes} bytes.")

    salt_hkdf_bits_actual_len = len_salt_hkdf_bytes * 8
    if len(all_extracted_bits_from_video) < current_read_idx + salt_hkdf_bits_actual_len: print_error_and_exit_extract("Bit tidak cukup untuk salt HKDF.", cap); return False
    salt_hkdf_bits = all_extracted_bits_from_video[current_read_idx : current_read_idx + salt_hkdf_bits_actual_len]; current_read_idx += salt_hkdf_bits_actual_len
    try: salt_hkdf_bytes_extracted = bitstream_ke_bytes(salt_hkdf_bits)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi salt HKDF bits ke bytes: {e}", cap); return False
    print(f"Salt HKDF diekstrak ({len(salt_hkdf_bytes_extracted)} bytes).")

    # 4. Hitung Shared Secret dan Derivasi Kunci AES (oleh Penerima)
    try:
        pengirim_pub_ecc_obj_remote = deserialisasi_kunci_publik_ecc_compressed(pengirim_pub_ecc_bytes_extracted)
        shared_secret_penerima_bytes = buat_shared_secret_ecdh(kunci_privat_ecc_penerima, pengirim_pub_ecc_obj_remote)
        kunci_aes_derived_penerima = derive_kunci_aes_dari_shared_secret(shared_secret_penerima_bytes, salt_hkdf_bytes_extracted, 32)
        print("Shared secret dan kunci AES berhasil diderivasi oleh penerima.")
    except Exception as e:
        print_error_and_exit_extract(f"Error saat ECDH atau derivasi kunci AES penerima: {e}", cap); return False

    # 5. Parse Info AES (Nonce, Tag, Panjang Ciphertext)
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
    print(f"Panjang Ciphertext diharapkan: {len_ciphertext_bytes} bytes.")

    # 6. Ekstrak Ciphertext Gambar (lanjutkan baca frame jika perlu)
    ciphertext_bits_len_needed = len_ciphertext_bytes * 8
    ciphertext_bits_collected = all_extracted_bits_from_video[current_read_idx:] # Ambil sisa bit dari frame pertama
    
    frame_num_extract = 1 # Sudah proses frame 1
    # Cek apakah semua ciphertext sudah ada di frame pertama
    if len(ciphertext_bits_collected) < ciphertext_bits_len_needed:
        print(f"Ciphertext belum lengkap ({len(ciphertext_bits_collected)}/{ciphertext_bits_len_needed} bits). Melanjutkan ke frame berikutnya...")
        while len(ciphertext_bits_collected) < ciphertext_bits_len_needed:
            frame_num_extract += 1; ret, frame = cap.read()
            if not ret: print(f"Warning: Video selesai sebelum semua ciphertext ({ciphertext_bits_len_needed}) diekstrak. Baru dapat {len(ciphertext_bits_collected)}."); break
            cropped_stego_frame = frame[0:processed_h, 0:processed_w]
            # print(f"Mengekstrak sisa ciphertext dari frame {frame_num_extract}...")
            bits_from_current_frame = proses_frame_qim_dct(cropped_stego_frame, 'extract', delta_kuantisasi, num_ac_coeffs_to_use=num_ac_coeffs)
            ciphertext_bits_collected += bits_from_current_frame
            # print(f"  Bit dari frame ini: {len(bits_from_current_frame)}. Total bit ciphertext terkumpul: {len(ciphertext_bits_collected)}")
    
    if len(ciphertext_bits_collected) < ciphertext_bits_len_needed: print("Ekstraksi GAGAL: Ciphertext tidak lengkap."); cap.release(); return False
    
    final_ciphertext_bits = ciphertext_bits_collected[:ciphertext_bits_len_needed]
    try: final_ciphertext_bytes = bitstream_ke_bytes(final_ciphertext_bits)
    except ValueError as e: print_error_and_exit_extract(f"Error konversi ciphertext: {e}", cap); return False

    # 7. Dekripsi Gambar dengan Kunci AES yang Diderivasi Penerima
    print("Mendekripsi gambar dengan kunci AES yang diderivasi...")
    plaintext_gambar_bytes = dekripsi_aes_gcm(final_ciphertext_bytes, kunci_aes_derived_penerima, nonce_bytes_extracted, tag_bytes_extracted)
    if plaintext_gambar_bytes is None: print("Dekripsi GAGAL."); cap.release(); return False
    print("Dekripsi berhasil.")
    try: bitstream_gambar_dekripsi = bytes_ke_bitstream(plaintext_gambar_bytes)
    except Exception as e: print_error_and_exit_extract(f"Error konversi plaintext: {e}", cap); return False

    # 8. Rekonstruksi Gambar
    gambar_hasil_ekstraksi = steg_helpers.bitstream_ke_gambar(bitstream_gambar_dekripsi, secret_lebar, secret_tinggi)
    if gambar_hasil_ekstraksi:
        try: gambar_hasil_ekstraksi.save(path_gambar_output); print(f"Gambar (ECC-AES) diekstrak ke '{path_gambar_output}'.")
        except Exception as e: print_error_and_exit_extract(f"Error simpan gambar: {e}", cap); return False
    else: print_error_and_exit_extract("Gagal rekonstruksi gambar.", cap); return False
    
    cap.release(); print("Proses ekstraksi (ECC-AES) selesai."); return True

def print_error_and_exit_extract(message, cap_to_release=None): 
    print(f"Error Kritis Ekstraksi: {message}")
    if cap_to_release and cap_to_release.isOpened(): cap_to_release.release()

# --- Blok Utama untuk Menjalankan (Dimodifikasi untuk ECC-AES) ---
if __name__ == "__main__":
    # --- Setup folder input/output ---
    input_dir = "media/input"
    output_dir = "media/output"
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    video_input_path = os.path.join(input_dir, "cover.mp4")
    gambar_rahasia_path = os.path.join(input_dir, "ini_adalah_rahasia_grayscale.png")
    video_output_stego_base_path = os.path.join(output_dir, "stego_video_ecc_aes_output")
    path_gambar_hasil_ekstraksi_ecc_aes = os.path.join(output_dir, "extracted_ECC_AES_secret_image.png")

    # Parameter yang berhasil sebelumnya (atau bisa disesuaikan)
    DELTA_UNTUK_TES = 20 # Kembali ke DELTA yang lebih kecil yang berhasil untuk AES biasa
    JUMLAH_AC_KOEFISIEN_DIPAKAI = 10 # Atau 17 jika itu yang terakhir berhasil

    # --- Setup Kunci ECC untuk Penerima (Bob) ---
    if not os.path.exists("bob_private_key.pem"):
        print("Membuat pasangan kunci ECC untuk Penerima (Bob)...")
        bob_private_ecc, bob_public_ecc = buat_pasangan_kunci_ecc()
        with open("bob_private_key.pem", "wb") as f:
            f.write(bob_private_ecc.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("bob_public_key.pem", "wb") as f:
            f.write(bob_public_ecc.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Kunci ECC Bob disimpan ke bob_private_key.pem dan bob_public_key.pem")
    else:
        print("Menggunakan kunci ECC Bob yang sudah ada...")
        with open("bob_private_key.pem", "rb") as f:
            bob_private_ecc = serialization.load_pem_private_key(f.read(), password=None)
        with open("bob_public_key.pem", "rb") as f:
            bob_public_ecc = serialization.load_pem_public_key(f.read())
    bob_public_key_bytes_compressed = serialisasi_kunci_publik_ecc_compressed(bob_public_ecc)
    
    # Buat file dummy jika perlu
    if not os.path.exists(gambar_rahasia_path):
        try: Image.new('L', (64, 64), color='lightgray').save(gambar_rahasia_path); print(f"INFO: Gambar dummy '{gambar_rahasia_path}' dibuat.")
        except Exception as e: print(f"ERROR: Gagal buat gambar dummy: {e}")
    if not os.path.exists(video_input_path):
        try:
            out_dummy = cv2.VideoWriter(video_input_path, cv2.VideoWriter_fourcc(*'mp4v'), 24.0, (640,480))
            for _ in range(24*5): out_dummy.write(np.random.randint(0,256,(480,640,3),dtype=np.uint8))
            out_dummy.release(); print(f"INFO: Video dummy '{video_input_path}' dibuat. Jalankan lagi.")
        except Exception as e: print(f"ERROR: Gagal buat video dummy: {e}")

    if os.path.exists(video_input_path) and os.path.exists(gambar_rahasia_path):
        print(f"\nMEMULAI PROSES EMBEDDING (ECC-AES) UTAMA KE FILE VIDEO")
        print(f"DELTA = {DELTA_UNTUK_TES}, Jumlah Koefisien AC per Blok = {JUMLAH_AC_KOEFISIEN_DIPAKAI}")
        
        stego_video_file_path_ecc_aes = video_output_stego_base_path 
        
        berhasil_embed_ecc_aes, first_stego_frame_gray_for_psnr = embed_gambar_ke_video_ecc_aes(
            video_input_path, 
            gambar_rahasia_path, 
            stego_video_file_path_ecc_aes, 
            DELTA_UNTUK_TES,
            JUMLAH_AC_KOEFISIEN_DIPAKAI,
            bob_public_key_bytes_compressed 
        )

        if berhasil_embed_ecc_aes:
            actual_stego_avi_path = steg_helpers.get_avi_path(stego_video_file_path_ecc_aes) 
            print("\nEMBEDDING GAMBAR (ECC-AES) KE FILE VIDEO SELESAI DENGAN SUKSES.")
            print(f"Video output disimpan di: {actual_stego_avi_path}")

            # --- HITUNG PSNR SETELAH EMBEDDING ECC-AES ---
            if first_stego_frame_gray_for_psnr is not None:
                cap_temp_orig = cv2.VideoCapture(video_input_path)
                ret_temp_orig, first_frame_color_orig = cap_temp_orig.read()
                if ret_temp_orig:
                    h_proc = (first_frame_color_orig.shape[0] // 8) * 8
                    w_proc = (first_frame_color_orig.shape[1] // 8) * 8
                    original_frame_gray_for_psnr = cv2.cvtColor(first_frame_color_orig[0:h_proc, 0:w_proc], cv2.COLOR_BGR2GRAY)
                    
                    psnr_ecc_aes_embed = cv2.PSNR(original_frame_gray_for_psnr, first_stego_frame_gray_for_psnr)
                    print(f"PSNR frame pertama (asli vs stego ECC-AES): {psnr_ecc_aes_embed:.2f} dB")
                if cap_temp_orig.isOpened(): cap_temp_orig.release()
            # --------------------------------------------
            
            print("\nMEMULAI PROSES EKSTRAKSI (ECC-AES) DARI FILE VIDEO...")
            berhasil_ekstrak_ecc_aes = ekstraksi_gambar_video_ecc_aes(
                actual_stego_avi_path, 
                path_gambar_hasil_ekstraksi_ecc_aes, 
                DELTA_UNTUK_TES,
                JUMLAH_AC_KOEFISIEN_DIPAKAI,
                bob_private_ecc 
            )
            if berhasil_ekstrak_ecc_aes:
                print("\nVERIFIKASI EKSTRAKSI (ECC-AES) DARI FILE BERHASIL!")
                print(f"Gambar rahasia telah diekstrak ke: {path_gambar_hasil_ekstraksi_ecc_aes}")
                try:
                    img_asli = Image.open(gambar_rahasia_path).convert('L')
                    img_ekstrak = Image.open(path_gambar_hasil_ekstraksi_ecc_aes).convert('L')
                    if np.array_equal(np.array(img_asli), np.array(img_ekstrak)):
                        print("Pengecekan piksel: Gambar asli dan hasil ekstraksi (ECC-AES) IDENTIK.")
                    else:
                        print("Pengecekan piksel: Gambar asli dan hasil ekstraksi (ECC-AES) BERBEDA.")
                except Exception as e_compare:
                    print(f"Error saat membandingkan gambar: {e_compare}")
            else:
                print("\nVERIFIKASI EKSTRAKSI (ECC-AES) DARI FILE GAGAL.")
        else:
            print("\nEMBEDDING GAMBAR (ECC-AES) KE FILE VIDEO GAGAL.")
    else:
        print("\nEmbedding tidak bisa dimulai karena file input tidak ditemukan.")

