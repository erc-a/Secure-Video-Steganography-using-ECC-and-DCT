import sys, os
import time
import cv2
import numpy as np
import csv
from datetime import datetime

# === Path Fix for Relative Import ===
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from steg.crypto_utils import (
    buat_pasangan_kunci_ecc, buat_shared_secret_ecdh,
    derive_kunci_aes_dari_shared_secret,
    enkripsi_aes_gcm, dekripsi_aes_gcm
)
from steg.qim_dct import proses_frame_qim_dct

# === Output Folder Setup ===
OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'results'))
os.makedirs(OUTPUT_DIR, exist_ok=True)

CSV_PATH = os.path.join(OUTPUT_DIR, "benchmark_results.csv")
TXT_PATH = os.path.join(OUTPUT_DIR, "benchmark_results.txt")
MD_PATH  = os.path.join(OUTPUT_DIR, "benchmark_results.md")

results = []
def write_results_to_csv():
    with open(CSV_PATH, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([f"# Benchmark Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        writer.writerow(["Kategori", "Metode", "Nilai", "Catatan"])
        for row in results:
            writer.writerow(row)

def write_results_to_txt():
    with open(TXT_PATH, mode='w') as f:
        f.write(f"Benchmark Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        current = ""
        for row in results:
            if row[0] != current:
                current = row[0]
                f.write(f"[{current}]\n")
            f.write(f"- {row[1]:<25}: {row[2]} ({row[3]})\n")

def write_results_to_md():
    with open(MD_PATH, mode='w', encoding='utf-8') as f:
        f.write(f"# Benchmark Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        categories = {}
        for row in results:
            cat = row[0]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(row[1:])
        for cat, items in categories.items():
            f.write(f"## {'🔐' if cat == 'Kriptografi' else '🕵️‍♀️'} {cat}\n\n")
            f.write("| Metode | Nilai | Catatan |\n")
            f.write("|--------|--------|---------|\n")
            for item in items:
                f.write(f"| {item[0]} | {item[1]} | {item[2]} |\n")
            f.write("\n")

def test_brute_force_ecc_simulasi(n_iter=500):
    print("\n[TEST] Keamanan ECC - Brute Force Simulation")
    start = time.perf_counter()
    for _ in range(n_iter):
        buat_pasangan_kunci_ecc()
    duration = time.perf_counter() - start
    avg_time = duration / n_iter
    estimated_years = 2**128 * avg_time / (60 * 60 * 24 * 365)
    print(f"[ECC] Avg gen time: {avg_time:.6f} sec")
    print(f"[ECC] Estimated brute-force time (128-bit): ~{estimated_years:.2e} years")
    results.append(["Kriptografi", "ECC Key Generation", f"{avg_time:.6f} detik", f"rata-rata {n_iter} iterasi"])
    results.append(["Kriptografi", "ECC Brute-force Estimate", "2^128", f"~{estimated_years:.2e} tahun"])

def test_waktu_enkripsi_dekripsi(payload_size=1024):
    print("\n[TEST] Waktu Enkripsi & Dekripsi AES + ECC")
    data = os.urandom(payload_size)
    priv, pub = buat_pasangan_kunci_ecc()
    shared = buat_shared_secret_ecdh(priv, pub)
    key = derive_kunci_aes_dari_shared_secret(shared, os.urandom(16))

    start = time.perf_counter()
    ct, nonce, tag = enkripsi_aes_gcm(data, key)
    enc_time = time.perf_counter() - start

    start = time.perf_counter()
    pt = dekripsi_aes_gcm(ct, key, nonce, tag)
    dec_time = time.perf_counter() - start

    assert pt == data
    print(f"[AES] Encrypt: {enc_time:.6f}s | Decrypt: {dec_time:.6f}s")
    results.append(["Kriptografi", "AES Encrypt", f"{enc_time:.6f} detik", f"{payload_size}-byte payload"])
    results.append(["Kriptografi", "AES Decrypt", f"{dec_time:.6f} detik", f"{payload_size}-byte payload"])

def test_psnr(original_gray, stego_gray):
    print("\n[TEST] PSNR Frame Asli vs Stego")
    psnr_val = cv2.PSNR(original_gray, stego_gray)
    print(f"[PSNR] {psnr_val:.2f} dB")
    results.append(["Steganografi", "PSNR", f"{psnr_val:.2f} dB", "frame pertama (grayscale)"])
    return psnr_val

def estimate_capacity_per_frame(frame_width, frame_height, ac_coeffs):
    print("\n[TEST] Capacity per Frame")
    blocks = (frame_width // 8) * (frame_height // 8)
    capacity = blocks * ac_coeffs
    print(f"[Capacity] {capacity} bits per frame")
    results.append(["Steganografi", "Capacity", f"{capacity} bit/frame", f"resolusi: {frame_width}x{frame_height}, {ac_coeffs} AC/block"])
    return capacity

def load_test_images():
    print("\n[LOAD] Membuat citra dummy dan menyisipkan payload...")
    dummy_gray = np.random.randint(0, 256, (240, 320), dtype=np.uint8)
    bits = ''.join(np.random.choice(['0', '1'], size=1024))
    _, stego, used = proses_frame_qim_dct(dummy_gray, 'embed', 20, bits, num_ac_coeffs_to_use=10)
    print("[LOAD] Payload embedded.")
    return dummy_gray, stego

def test_robustness_note():
    print("\n[NOTE] Robustness belum diuji otomatis. Butuh uji manual: re-encode, crop, dll.")
    results.append(["Steganografi", "Robustness", "N/A", "perlu pengujian re-encode/cropping manual"])

def run_all_tests():
    test_brute_force_ecc_simulasi(500)
    test_waktu_enkripsi_dekripsi(1024)
    orig, stego = load_test_images()
    test_psnr(orig, stego)
    estimate_capacity_per_frame(320, 240, 10)
    test_robustness_note()
    write_results_to_csv()
    write_results_to_txt()
    write_results_to_md()
    print(f"\n[FINISHED] Semua hasil disimpan di:\n - {CSV_PATH}\n - {TXT_PATH}\n - {MD_PATH}")

if __name__ == '__main__':
    run_all_tests()
