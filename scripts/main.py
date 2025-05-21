# === File: main.py ===
import os
import sys
import cv2
import numpy as np
from PIL import Image

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from steg.helpers import gambar_ke_bitstream, bitstream_ke_gambar, buat_metadata_bitstream, parse_metadata_bitstream, get_avi_path
from steg.crypto_utils import *
from steg.qim_dct import proses_frame_qim_dct


def embed_wrapper(video_in, img_secret, video_out_base, delta, ac_coeffs, pub_key_bytes):
    print("\n[EMBED] Preparing bitstream...")
    w, h, bitstream = gambar_ke_bitstream(img_secret)
    img_bytes = bitstream_ke_bytes(bitstream)
    hash_bytes = hitung_sha3_256(img_bytes)
    metadata_bits = buat_metadata_bitstream(w, h)

    eph_priv, eph_pub = buat_pasangan_kunci_ecc()
    shared_secret = buat_shared_secret_ecdh(eph_priv, deserialisasi_kunci_publik_ecc_compressed(pub_key_bytes))
    salt = os.urandom(16)
    aes_key = derive_kunci_aes_dari_shared_secret(shared_secret, salt)
    ciphertext, nonce, tag = enkripsi_aes_gcm(img_bytes, aes_key)

    payload = (
        metadata_bits +
        int_ke_bitstream(len(serialisasi_kunci_publik_ecc_compressed(eph_pub)), 8) +
        bytes_ke_bitstream(serialisasi_kunci_publik_ecc_compressed(eph_pub)) +
        int_ke_bitstream(len(salt), 8) + bytes_ke_bitstream(salt) +
        int_ke_bitstream(len(hash_bytes), 8) + bytes_ke_bitstream(hash_bytes) +
        int_ke_bitstream(len(nonce), 8) + bytes_ke_bitstream(nonce) +
        int_ke_bitstream(len(tag), 8) + bytes_ke_bitstream(tag) +
        int_ke_bitstream(len(ciphertext), 32) + bytes_ke_bitstream(ciphertext)
    )

    print("[EMBED] Embedding payload...")
    cap = cv2.VideoCapture(video_in)
    fourcc = cv2.VideoWriter_fourcc(*'F','F','V','1')
    w_in = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h_in = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    out_w, out_h = (w_in//8)*8, (h_in//8)*8
    out_path = get_avi_path(video_out_base)
    out = cv2.VideoWriter(out_path, fourcc, fps, (out_w, out_h), True)

    idx, frame_id = 0, 0
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret: break
        frame_id += 1
        cropped = frame[:out_h,:out_w]
        if idx < len(payload):
            bits = payload[idx:]
            _, stego, used = proses_frame_qim_dct(cropped, 'embed', delta, bits, ac_coeffs)
            out.write(cv2.cvtColor(stego, cv2.COLOR_GRAY2BGR))
            idx += used
        else:
            out.write(cropped)
    cap.release()
    out.release()
    print("[EMBED] Done. Output:", out_path)


def extract_wrapper(video_path, out_img_path, priv_key):
    print("\n[EXTRACT] Extracting payload...")
    cap = cv2.VideoCapture(video_path)
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    usable_w, usable_h = (w//8)*8, (h//8)*8
    bits = ""
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret: break
        cropped = frame[:usable_h,:usable_w]
        bits += proses_frame_qim_dct(cropped, 'extract', delta=20, num_ac_coeffs_to_use=10)
    cap.release()

    try:
        meta = bits[:32]; bits = bits[32:]
        w, h = parse_metadata_bitstream(meta)
        len_pub = bitstream_ke_int(bits[:8]); bits = bits[8:]
        pub_bytes = bitstream_ke_bytes(bits[:len_pub*8]); bits = bits[len_pub*8:]
        len_salt = bitstream_ke_int(bits[:8]); bits = bits[8:]
        salt = bitstream_ke_bytes(bits[:len_salt*8]); bits = bits[len_salt*8:]
        len_hash = bitstream_ke_int(bits[:8]); bits = bits[8:]
        hash_stego = bitstream_ke_bytes(bits[:len_hash*8]); bits = bits[len_hash*8:]
        len_nonce = bitstream_ke_int(bits[:8]); bits = bits[8:]
        nonce = bitstream_ke_bytes(bits[:len_nonce*8]); bits = bits[len_nonce*8:]
        len_tag = bitstream_ke_int(bits[:8]); bits = bits[8:]
        tag = bitstream_ke_bytes(bits[:len_tag*8]); bits = bits[len_tag*8:]
        len_ct = bitstream_ke_int(bits[:32]); bits = bits[32:]
        ct = bitstream_ke_bytes(bits[:len_ct*8])

        pub = deserialisasi_kunci_publik_ecc_compressed(pub_bytes)
        shared_secret = buat_shared_secret_ecdh(priv_key, pub)
        aes_key = derive_kunci_aes_dari_shared_secret(shared_secret, salt)
        plaintext = dekripsi_aes_gcm(ct, aes_key, nonce, tag)

        if plaintext and hitung_sha3_256(plaintext) == hash_stego:
            img = bitstream_ke_gambar(bytes_ke_bitstream(plaintext), w, h)
            img.save(out_img_path)
            print("[EXTRACT] Success. Output:", out_img_path)
        else:
            print("[EXTRACT] Failed: Integrity check mismatch or decryption error.")
    except Exception as e:
        print("[EXTRACT] Error:", e)


if __name__ == '__main__':
    video_input = "media/input/cover.mp4"
    secret_img = "media/input/ini_adalah_rahasia_grayscale.png"
    video_output_base = "media/output/stego_video_final_output"
    extracted_img = "media/output/extracted_FINAL_secret_image.png"

    if not os.path.exists(secret_img):
        Image.new('L', (32, 32), color='lightgray').save(secret_img)
    if not os.path.exists(video_input):
        out = cv2.VideoWriter(video_input, cv2.VideoWriter_fourcc(*'mp4v'), 24, (640, 480))
        for _ in range(120):
            out.write(np.random.randint(0,256,(480,640,3),dtype=np.uint8))
        out.release()

    priv, pub = buat_pasangan_kunci_ecc()
    pub_bytes = serialisasi_kunci_publik_ecc_compressed(pub)

    embed_wrapper(video_input, secret_img, video_output_base, delta=20, ac_coeffs=10, pub_key_bytes=pub_bytes)
    extract_wrapper(get_avi_path(video_output_base), extracted_img, priv)
