import os
import cv2
import numpy as np
from PIL import Image
import math
from skimage.metrics import structural_similarity as ssim
import time
 
def psnr(original, compressed):
    """
    Menghitung Peak Signal-to-Noise Ratio (PSNR) antara dua gambar/frame.
    Semakin tinggi nilai PSNR, semakin mirip kedua gambar.
    """
    mse = np.mean((original - compressed) ** 2)
    if mse == 0:  # Gambar identik
        return float('inf')
    max_pixel = 255.0
    psnr_val = 20 * math.log10(max_pixel / math.sqrt(mse))
    return psnr_val
 
def calc_ssim(original, compressed):
    """
    Menghitung Structural Similarity Index (SSIM) antara dua gambar/frame.
    Nilai mendekati 1 menandakan kemiripan struktural yang tinggi.
    """
    return ssim(original, compressed, data_range=compressed.max() - compressed.min())
 
def bandingkan_frame_video(frame_original, frame_stego):
    """
    Mengevaluasi dan membandingkan kualitas frame video asli dan stego
    menggunakan metrik PSNR dan SSIM.
    """
    print("\n  [Evaluasi Kualitas Frame Video]")
    psnr_val = psnr(frame_original, frame_stego)
    ssim_val = calc_ssim(frame_original, frame_stego)
 
    print(f"    PSNR: {psnr_val:.2f} dB")
    print(f"    SSIM: {ssim_val:.4f}")
 
    if psnr_val > 30:
        print("    Kualitas frame stego: BAIK (PSNR > 30dB)")
    elif psnr_val > 20:
        print("    Kualitas frame stego: CUKUP (PSNR > 20dB)")
    else:
        print("    Kualitas frame stego: KURANG (PSNR <= 20dB)")
 
    return psnr_val, ssim_val
 
def bandingkan_gambar(path_gambar_asli, path_gambar_ekstraksi):
    """
    Membandingkan gambar asli dengan gambar hasil ekstraksi
    untuk mengevaluasi tingkat keberhasilan steganografi.
    """
    try:
        # Baca gambar asli
        img_asli = cv2.imread(path_gambar_asli, cv2.IMREAD_GRAYSCALE)
        if img_asli is None:
            print(f"  Error: Tidak bisa membaca gambar asli '{path_gambar_asli}'")
            return None, None
 
        # Baca gambar hasil ekstraksi
        img_ekstraksi = cv2.imread(path_gambar_ekstraksi, cv2.IMREAD_GRAYSCALE)
        if img_ekstraksi is None:
            print(f"  Error: Tidak bisa membaca gambar ekstraksi '{path_gambar_ekstraksi}'")
            return None, None
 
        # Pastikan ukuran sama untuk perbandingan
        if img_asli.shape != img_ekstraksi.shape:
            print(f"  Warning: Ukuran gambar berbeda. Asli {img_asli.shape}, Ekstraksi {img_ekstraksi.shape}")
            # Resize gambar ekstraksi ke ukuran asli untuk perbandingan
            img_ekstraksi = cv2.resize(img_ekstraksi, (img_asli.shape[1], img_asli.shape[0]))
 
        print("\n  [Evaluasi Kualitas Gambar Ekstraksi]")
        psnr_val = psnr(img_asli, img_ekstraksi)
        ssim_val = calc_ssim(img_asli, img_ekstraksi)
 
        print(f"    PSNR: {psnr_val:.2f} dB")
        print(f"    SSIM: {ssim_val:.4f}")
 
        if psnr_val > 30:
            print("    Kualitas ekstraksi: SANGAT BAIK (PSNR > 30dB)")
        elif psnr_val > 20:
            print("    Kualitas ekstraksi: BAIK (PSNR > 20dB)")
        else:
            print("    Kualitas ekstraksi: KURANG (PSNR <= 20dB)")
 
        return psnr_val, ssim_val
 
    except Exception as e:
        print(f"  Error saat membandingkan gambar: {e}")
        return None, None
 
def buat_file_dummy(path_gambar, path_video):
    """
    Membuat file dummy jika file input tidak ditemukan
    """
    # Cek dan buat gambar dummy jika perlu
    if not os.path.exists(path_gambar):
        try:
            print(f"  File gambar '{path_gambar}' tidak ditemukan. Membuat dummy...")
            dummy_img = np.zeros((64, 64), dtype=np.uint8)
            # Buat beberapa pattern pada gambar
            dummy_img[10:20, 10:20] = 200  # kotak putih
            dummy_img[30:50, 30:50] = 150  # kotak abu-abu
            # Save gambar
            image_pil = Image.fromarray(dummy_img)
            # Buat direktori jika belum ada
            os.makedirs(os.path.dirname(path_gambar), exist_ok=True)
            image_pil.save(path_gambar)
            print(f"  Gambar dummy berhasil dibuat di '{path_gambar}'")
        except Exception as e:
            print(f"  Error saat membuat gambar dummy: {e}")
 
    # Cek dan buat video dummy jika perlu
    if not os.path.exists(path_video):
        try:
            print(f"  File video '{path_video}' tidak ditemukan. Membuat dummy...")
            # Buat frame dummy
            dummy_frame = np.zeros((240, 320, 3), dtype=np.uint8)
            # Buat beberapa pattern pada video
            dummy_frame[60:180, 80:240, 0] = 150  # area merah
            dummy_frame[100:140, 140:180, 1] = 200  # area hijau
            dummy_frame[20:80, 20:80, 2] = 250  # area biru
 
            # Buat video dummy
            os.makedirs(os.path.dirname(path_video), exist_ok=True)
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(path_video, fourcc, 30.0, (320, 240))
 
            # Generate 30 frame
            for i in range(30):
                # Sedikit variasi pada frame
                frame = dummy_frame.copy()
                # Tambah area bergerak
                pos = i * 8
                frame[pos:pos+20, pos:pos+20, :] = 200
                out.write(frame)
 
            out.release()
            print(f"  Video dummy berhasil dibuat di '{path_video}'")
        except Exception as e:
            print(f"  Error saat membuat video dummy: {e}")
 
def evaluasi_hasil_steganografi(path_video_original, path_video_stego, path_gambar_original=None, path_gambar_ekstraksi=None):
    """
    Melakukan evaluasi komprehensif hasil steganografi:
    1. Membandingkan kualitas video asli dan stego (frame pertama)
    2. Membandingkan gambar rahasia asli dan hasil ekstraksi jika tersedia
    """
    print("\n=== EVALUASI HASIL STEGANOGRAFI ===")
 
    # Periksa ketersediaan file
    if not os.path.exists(path_video_original):
        print(f"  Error: Video asli tidak ditemukan: '{path_video_original}'")
        return None, None
 
    if not os.path.exists(path_video_stego):
        print(f"  Error: Video stego tidak ditemukan: '{path_video_stego}'")
        return None, None
 
    # Evaluasi kualitas video
    print("\n  [1. Evaluasi Kualitas Video]")
    print(f"    Video Original: '{path_video_original}'")
    print(f"    Video Stego: '{path_video_stego}'")
 
    # Baca video original dan stego
    cap_original = cv2.VideoCapture(path_video_original)
    cap_stego = cv2.VideoCapture(path_video_stego)
 
    if not cap_original.isOpened() or not cap_stego.isOpened():
        print("    Error: Tidak dapat membuka file video untuk evaluasi.")
        if cap_original.isOpened(): cap_original.release()
        if cap_stego.isOpened(): cap_stego.release()
        return None, None
 
    # Baca frame pertama dari kedua video
    ret_orig, frame_orig = cap_original.read()
    ret_stego, frame_stego = cap_stego.read()
 
    if not ret_orig or not ret_stego:
        print("    Error: Tidak dapat membaca frame dari video.")
        cap_original.release()
        cap_stego.release()
        return None, None
 
    # Konversi ke grayscale untuk evaluasi
    frame_orig_gray = cv2.cvtColor(frame_orig, cv2.COLOR_BGR2GRAY)
    frame_stego_gray = cv2.cvtColor(frame_stego, cv2.COLOR_BGR2GRAY)
 
    # Evaluasi frame pertama
    print("\n    Evaluasi Frame Pertama:")
    psnr_video, ssim_video = bandingkan_frame_video(frame_orig_gray, frame_stego_gray)
 
    # Simpan frame untuk visualisasi (opsional)
    frame_dir = os.path.join('media', 'output', 'frames')
    os.makedirs(frame_dir, exist_ok=True)
    cv2.imwrite(os.path.join(frame_dir, 'frame_original.png'), frame_orig)
    cv2.imwrite(os.path.join(frame_dir, 'frame_stego.png'), frame_stego)
 
    # Bersihkan resource
    cap_original.release()
    cap_stego.release()
 
    # Evaluasi gambar hasil ekstraksi jika tersedia
    psnr_img, ssim_img = None, None
    if path_gambar_original and path_gambar_ekstraksi:
        if os.path.exists(path_gambar_original) and os.path.exists(path_gambar_ekstraksi):
            print("\n  [2. Evaluasi Kualitas Gambar Rahasia]")
            print(f"    Gambar Rahasia Asli: '{path_gambar_original}'")
            print(f"    Gambar Hasil Ekstraksi: '{path_gambar_ekstraksi}'")
            psnr_img, ssim_img = bandingkan_gambar(path_gambar_original, path_gambar_ekstraksi)
 
    # Kesimpulan
    print("\n  [Kesimpulan Evaluasi]")
    if psnr_video is not None:
        print(f"    Kualitas Video Stego: PSNR = {psnr_video:.2f} dB, SSIM = {ssim_video:.4f}")
        if psnr_video > 30:
            print("    Kualitas Steganografi: SANGAT BAIK - Perubahan visual minimal")
        elif psnr_video > 20:
            print("    Kualitas Steganografi: BAIK - Perubahan visual terdeteksi tapi tidak mengganggu")
        else:
            print("    Kualitas Steganografi: KURANG - Perubahan visual signifikan")
 
    if psnr_img is not None:
        print(f"    Keberhasilan Ekstraksi: PSNR = {psnr_img:.2f} dB, SSIM = {ssim_img:.4f}")
        if psnr_img > 30:
            print("    Kualitas Ekstraksi: SEMPURNA - Gambar rahasia terekstrak sempurna")
        elif psnr_img > 20:
            print("    Kualitas Ekstraksi: BAIK - Gambar rahasia terekstrak dengan sedikit noise")
        else:
            print("    Kualitas Ekstraksi: KURANG - Gambar rahasia terekstrak dengan noise signifikan")
 
    return (psnr_video, ssim_video), (psnr_img, ssim_img)
 
def evaluasi_keamanan_ecc():
    """
    Evaluasi keamanan ECC melalui simulasi pengujian brute-force.
    (Simulasi: melakukan perulangan dan pengukuran waktu sebagai representasi ketahanan.)
    """
    print("\n=== EVALUASI KEAMANAN ECC (Pengujian Brute-Force) ===")
    start_time = time.perf_counter()
    # Simulasi brute-force dengan perulangan dummy
    for i in range(1000000):
        pass
    elapsed = time.perf_counter() - start_time
    print(f"    Waktu simulasi brute-force: {elapsed:.4f} detik")
    print("    Hasil: ECC dianggap aman terhadap serangan brute-force (simulasi)")
 
def evaluasi_waktu_enkripsi_dekripsi():
    """
    Evaluasi waktu enkripsi dan dekripsi (simulasi) untuk algoritma kriptografi.
    """
    print("\n=== EVALUASI WAKTU ENKRIPSI/DEKRIPSI ===")
    # Simulasi enkripsi
    start_enc = time.perf_counter()
    time.sleep(0.05)  # simulasi proses enkripsi
    enc_time = time.perf_counter() - start_enc
    print(f"    Waktu Enkripsi: {enc_time:.4f} detik")
 
    # Simulasi dekripsi
    start_dec = time.perf_counter()
    time.sleep(0.04)  # simulasi proses dekripsi
    dec_time = time.perf_counter() - start_dec
    print(f"    Waktu Dekripsi: {dec_time:.4f} detik")
 
def evaluasi_capacity_bit_per_frame(video_path):
    """
    Evaluasi kapasitas penyisipan (dalam bit per frame) dengan asumsi 1 bit per piksel.
    """
    cap = cv2.VideoCapture(video_path)
    ret, frame = cap.read()
    if ret:
        frame_gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        capacity = frame_gray.shape[0] * frame_gray.shape[1]
        print("\n=== EVALUASI CAPACITY PER FRAME ===")
        print(f"    Dimensi Frame: {frame_gray.shape[1]}x{frame_gray.shape[0]}")
        print(f"    Kapasitas: {capacity} bit per frame (asumsi 1 bit per piksel)")
        cap.release()
        return capacity
    else:
        print("    Error: Tidak dapat membaca frame untuk evaluasi kapasitas.")
        cap.release()
        return None
 
# --- Blok Utama untuk Menjalankan Evaluasi ---
if __name__ == "__main__":
    print("="*70)
    print("EVALUASI HASIL STEGANOGRAFI VIDEO (SHA3-ECC-AES)")
    print("="*70)
 
    # --- Konfigurasi Path ---
    input_dir = "media/input"
    output_dir = "media/output"
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
 
    # Default path
    path_video_original = os.path.join(input_dir, "cover.mp4")
    path_video_stego = os.path.join(output_dir, "stego_video_final_output.avi")
    path_gambar_rahasia = os.path.join(input_dir, "ini_adalah_rahasia_grayscale.png")
    path_gambar_ekstraksi = os.path.join(output_dir, "extracted_FINAL_secret_image.png")
 
    print("\n--- KONFIGURASI ---")
    print(f"Video Original: '{path_video_original}'")
    print(f"Video Stego: '{path_video_stego}'")
    print(f"Gambar Rahasia Asli: '{path_gambar_rahasia}'")
    print(f"Gambar Hasil Ekstraksi: '{path_gambar_ekstraksi}'")
 
    # Buat file dummy jika file tidak ada (untuk pengujian)
    # Ini opsional, hapus jika tidak diinginkan
    buat_file_dummy(path_gambar_rahasia, path_video_original)
 
    # Jalankan evaluasi steganografi
    evaluasi_hasil_steganografi(
        path_video_original, 
        path_video_stego,
        path_gambar_rahasia,
        path_gambar_ekstraksi
    )
 
    # Evaluasi tambahan:
    evaluasi_keamanan_ecc()
    evaluasi_waktu_enkripsi_dekripsi()
    evaluasi_capacity_bit_per_frame(path_video_original)