import cv2
import numpy as np
from scipy.fftpack import dct, idct
import os
from PIL import Image
# Impor helper untuk grayscale
import helpers as steg_helpers 

# Impor untuk AES, ECC, dan SHA3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes # Untuk SHA3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# --- Konfigurasi Global ---
_g_debug_print_count = 0
_MAX_DEBUG_PRINTS_PER_CALL = 0 # Set ke 0 untuk mematikan debug koefisien individual

# --- Fungsi Helper Bytes <-> Bitstream dan Int <-> Bitstream (SAMA) ---
def bytes_ke_bitstream(data_bytes):
    return ''.join(format(byte, '08b') for byte in data_bytes)

def bitstream_ke_bytes(bitstream_data):
    if len(bitstream_data) % 8 != 0:
        sisa = len(bitstream_data) % 8
        if sisa > 0: bitstream_data = bitstream_data[:-sisa]
        if not bitstream_data: raise ValueError("Bitstream kosong setelah dipotong.")
    return bytes(int(bitstream_data[i:i+8], 2) for i in range(0, len(bitstream_data), 8))

def int_ke_bitstream(nilai_int, jumlah_bit):
    if nilai_int < 0 or nilai_int >= (2**jumlah_bit):
        raise ValueError(f"Nilai {nilai_int} di luar jangkauan untuk {jumlah_bit} bit.")
    return format(nilai_int, f'0{jumlah_bit}b')

def bitstream_ke_int(bitstream_nilai, jumlah_bit_diharapkan=None):
    if jumlah_bit_diharapkan and len(bitstream_nilai) != jumlah_bit_diharapkan:
        raise ValueError(f"Panjang bitstream {len(bitstream_nilai)} tidak sesuai.")
    if not bitstream_nilai: raise ValueError("String bit kosong.")
    return int(bitstream_nilai, 2)

# --- Fungsi Enkripsi dan Dekripsi AES-GCM (SAMA) ---
def enkripsi_aes_gcm(data_bytes, kunci_aes_derived):
    if len(kunci_aes_derived) not in (16, 24, 32): 
        raise ValueError("Kunci AES harus 16, 24, atau 32 byte.")
    aesgcm = AESGCM(kunci_aes_derived)
    nonce = os.urandom(12) 
    ciphertext_with_tag = aesgcm.encrypt(nonce, data_bytes, None)
    tag_length = 16 
    if len(ciphertext_with_tag) < tag_length:
        raise ValueError("Hasil enkripsi AESGCM terlalu pendek.")
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
        print("Error Dekripsi AES: Tag autentikasi tidak valid.")
        return None
    except Exception as e:
        print(f"Error Dekripsi AES lainnya: {e}")
        return None

# --- Fungsi Helper ECC / ECDH (SAMA) ---
def buat_pasangan_kunci_ecc():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialisasi_kunci_publik_ecc_compressed(public_key_ecc):
    return public_key_ecc.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

def deserialisasi_kunci_publik_ecc_compressed(public_key_bytes_compressed, kurva=ec.SECP256R1()):
    return ec.EllipticCurvePublicKey.from_encoded_point(kurva, public_key_bytes_compressed)

def buat_shared_secret_ecdh(private_key_lokal_ecc, public_key_remote_ecc):
    shared_secret = private_key_lokal_ecc.exchange(ec.ECDH(), public_key_remote_ecc)
    return shared_secret

def derive_kunci_aes_dari_shared_secret(shared_secret_bytes, salt_bytes=None, panjang_kunci_aes_bytes=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=panjang_kunci_aes_bytes, 
        salt=salt_bytes, info=b'kunci aes untuk steganografi video', 
    )
    return hkdf.derive(shared_secret_bytes)

# --- Fungsi SHA3 ---
def hitung_sha3_256(data_bytes):
    """Menghitung hash SHA3-256 dari data bytes."""
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(data_bytes)
    return digest.finalize()

# --- Fungsi proses_frame_qim_dct (Grayscale, dari versi terakhir yang berhasil) ---
def proses_frame_qim_dct(frame_bgr_input, mode, delta, 
                         bit_payload_segment=None, 
                         enable_debug_prints_extract=False,
                         num_ac_coeffs_to_use=63):
    global _g_debug_print_count 
    if len(frame_bgr_input.shape) == 3 and frame_bgr_input.shape[2] == 3: 
        gray_frame_reference_uint8 = cv2.cvtColor(frame_bgr_input, cv2.COLOR_BGR2GRAY)
    elif len(frame_bgr_input.shape) == 2: 
        gray_frame_reference_uint8 = frame_bgr_input.copy()
    else:
        raise ValueError("Format frame input tidak didukung.")
    img_to_process_float = np.float32(gray_frame_reference_uint8) 
    height, width = img_to_process_float.shape
    block_size = 8
    output_pixel_data_float = img_to_process_float.copy() 
    extracted_bits_list = [] 
    current_payload_bit_idx = 0 
    bits_processed_in_this_frame = 0 
    max_bits_to_embed_from_segment = 0
    if mode == 'embed' and bit_payload_segment:
        max_bits_to_embed_from_segment = len(bit_payload_segment)
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

# --- Setup Kunci ECC ---
def setup_kunci_ecc():
    print("="*70)
    print("SETUP KUNCI ECC UNTUK STEGANOGRAFI VIDEO (SHA3-ECC-AES)")
    print("="*70)
    
    # Setup Kunci ECC Penerima
    print("\n--- SETUP KUNCI ECC PENERIMA (BOB) ---")
    if not os.path.exists("bob_private_key.pem") or not os.path.exists("bob_public_key.pem"):
        print("  Membuat pasangan kunci ECC baru untuk Penerima (Bob)...")
        bob_private_ecc, bob_public_ecc = buat_pasangan_kunci_ecc()
        try:
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
            print("  Kunci ECC Bob berhasil dibuat dan disimpan ke 'bob_private_key.pem' dan 'bob_public_key.pem'.")
        except Exception as e_key_save:
            print(f"  Error saat menyimpan kunci ECC Bob: {e_key_save}")
            return None, None
    else:
        print("  Menggunakan kunci ECC Bob yang sudah ada dari file.")
    
    try:
        with open("bob_private_key.pem", "rb") as f:
            bob_private_ecc = serialization.load_pem_private_key(f.read(), password=None)
        with open("bob_public_key.pem", "rb") as f:
            bob_public_ecc = serialization.load_pem_public_key(f.read())
        bob_public_key_bytes_compressed = serialisasi_kunci_publik_ecc_compressed(bob_public_ecc)
        print("  Kunci ECC Bob berhasil dimuat.")
        return bob_private_ecc, bob_public_key_bytes_compressed
    except Exception as e_key_load:
        print(f"  Error saat memuat kunci ECC Bob: {e_key_load}")
        return None, None

# --- Persiapan File Input ---
def persiapkan_file_input(input_dir, video_input_path, gambar_rahasia_path):
    os.makedirs(input_dir, exist_ok=True)
    
    # Buat file dummy jika perlu
    if not os.path.exists(gambar_rahasia_path):
        try: 
            Image.new('L', (32, 32), color='lightgray').save(gambar_rahasia_path)
            print(f"  INFO: Gambar dummy '{gambar_rahasia_path}' (32x32) dibuat.")
        except Exception as e: 
            print(f"  ERROR: Gagal buat gambar dummy: {e}")
    
    if not os.path.exists(video_input_path):
        try:
            out_dummy = cv2.VideoWriter(video_input_path, cv2.VideoWriter_fourcc(*'mp4v'), 24.0, (640,480))
            for _ in range(24*5): out_dummy.write(np.random.randint(0,256,(480,640,3),dtype=np.uint8))
            out_dummy.release(); print(f"  INFO: Video dummy '{video_input_path}' dibuat. Jalankan lagi.")
        except Exception as e: 
            print(f"  ERROR: Gagal buat video dummy: {e}")
    
    return os.path.exists(video_input_path) and os.path.exists(gambar_rahasia_path)

# --- Blok Utama untuk Menjalankan Setup ---
if __name__ == "__main__":
    print("="*70)
    print("KONFIGURASI DAN SETUP UNTUK STEGANOGRAFI VIDEO (SHA3-ECC-AES)")
    print("="*70)

    # --- Konfigurasi Eksperimen ---
    input_dir = "media/input"
    output_dir = "media/output"
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    video_input_path = os.path.join(input_dir, "cover.mp4")
    gambar_rahasia_path = os.path.join(input_dir, "ini_adalah_rahasia_grayscale.png") # Gambar grayscale
    
    print("\n--- KONFIGURASI ---")
    print(f"  Video Input: '{video_input_path}'")
    print(f"  Gambar Rahasia: '{gambar_rahasia_path}'")
    
    # Persiapkan file input
    file_siap = persiapkan_file_input(input_dir, video_input_path, gambar_rahasia_path)
    
    # Setup kunci
    bob_private_ecc, bob_public_key_bytes_compressed = setup_kunci_ecc()
    
    if bob_private_ecc and bob_public_key_bytes_compressed and file_siap:
        print("\nStatus: KONFIGURASI DAN SETUP SELESAI DENGAN SUKSES")
        print("File input dan kunci ECC siap untuk proses steganografi")
    else:
        print("\nStatus: KONFIGURASI DAN SETUP TIDAK LENGKAP")
        if not file_siap:
            print("Masalah: File input tidak lengkap")
        if not bob_private_ecc or not bob_public_key_bytes_compressed:
            print("Masalah: Setup kunci ECC tidak berhasil")
    
    print("\nPROGRAM SELESAI")
    print("="*70)