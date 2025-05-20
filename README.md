# Secure-Video-Steganography-using-ECC-and-DCT

Proyek ini mengimplementasikan steganografi video yang aman dengan mengenkripsi gambar rahasia menggunakan Elliptic Curve Cryptography (ECC) dan Advanced Encryption Standard (AES), lalu menyisipkannya ke dalam video menggunakan teknik Discrete Cosine Transform (DCT).

## Anggota Kelompok (Kelompok 5 Kelas RB)
- Eric Arwido Damanik (122140157)
- Alwi Arfan Solin (122140197)
- Jhoel Robert Hutagalung (122140174)
- Andre Tampubolon (122140194)
- Dyo Bukit (122140145)
- Gabriela Rumapea (122140056)

## Mata Kuliah
- Kriptografi
- Dosen : Ilham Firman Ashari, S.Kom., M.T.

## Deskripsi Proyek
Proyek ini menggabungkan dua metode utama:
1. **Elliptic Curve Cryptography (ECC) + AES**
   - Gambar rahasia dienkripsi menggunakan kunci simetris AES-256.
   - Kunci AES dihasilkan secara aman melalui pertukaran kunci ECC (ECDH).
2. **Discrete Cosine Transform (DCT)**
   - Data gambar yang sudah terenkripsi disisipkan ke dalam frame video pada domain frekuensi menggunakan DCT.

### Fitur Utama
- Enkripsi gambar rahasia menggunakan kombinasi ECC dan AES.
- Penyisipan data ke dalam video menggunakan DCT.
- Ekstraksi dan dekripsi gambar dari video stego.
- Semua file input berada di `media/input` dan output di `media/output`.

---

## Instalasi & Persiapan Lingkungan

### 1. Clone Repository
```bash
git clone https://github.com/erc-a/Secure-Video-Steganography-using-ECC-and-DCT.git
cd Secure-Video-Steganography-using-ECC-and-DCT
```

### 2. Buat Environment Conda (Python 3.11)
Disarankan menggunakan Python 3.11 untuk kompatibilitas library.
```bash
conda create -n tubes_kripto python=3.11
conda activate tubes_kripto
```

### 3. Install Library yang Dibutuhkan
Pastikan Anda sudah berada di folder project, lalu jalankan:
```bash
pip install -r requirements.txt
```
**Library utama yang digunakan:**
- numpy
- opencv-python
- pillow
- scipy
- cryptography

---

## Struktur Folder
- `media/input/` : Tempat file input (video cover, gambar rahasia)
- `media/output/` : Tempat file output (video stego, hasil ekstraksi gambar)

---

## Cara Menjalankan Program

1. **Siapkan file input:**
   - Letakkan video cover (misal: `cover.mp4`) dan gambar rahasia (misal: `ini_adalah_rahasia_grayscale.png`) di folder `media/input/`.
   - Jika file tidak ada, program akan membuat file dummy secara otomatis.

2. **Jalankan program utama:**
   ```bash
   python main.py
   ```
   - Proses embedding dan ekstraksi akan berjalan otomatis.
   - Hasil video stego dan gambar hasil ekstraksi akan muncul di folder `media/output/`.

---

## Catatan
- Kunci privat dan publik ECC akan otomatis dibuat jika belum ada.
- Pastikan semua dependensi sudah terinstall sesuai `requirements.txt`.
- Untuk penggunaan di luar Windows, pastikan codec video yang digunakan didukung oleh sistem Anda.

---

## Lisensi
Proyek ini hanya untuk keperluan pembelajaran.
