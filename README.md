# Secure-Video-Steganography-using-ECC-and-DCT

Proyek ini mengimplementasikan sistem steganografi video yang **aman dan efisien**, dengan mengenkripsi gambar rahasia menggunakan **Elliptic Curve Cryptography (ECC)** dan **Advanced Encryption Standard (AES-GCM)**, lalu menyisipkannya ke dalam frame video menggunakan transformasi frekuensi **Discrete Cosine Transform (DCT)** dengan **Quantization Index Modulation (QIM)**.

---

## 👥 Anggota Kelompok (Kelompok 5 Kelas RB)

* Eric Arwido Damanik (122140157)
* Alwi Arfan Solin (122140197)
* Jhoel Robert Hutagalung (122140174)
* Andre Tampubolon (122140194)
* Dyo Bukit (122140145)
* Gabriela Rumapea (122140056)

### Mata Kuliah

**Kriptografi**
Dosen: *Ilham Firman Ashari, S.Kom., M.T.*

---

## 🔐 Deskripsi Proyek

Proyek ini menggabungkan tiga teknik utama:

1. **Enkripsi Gambar dengan ECC + AES-GCM**

   * Kunci AES 256-bit dihasilkan melalui pertukaran kunci ECC (ECDH).
   * Gambar rahasia dienkripsi menggunakan AES dalam mode Galois/Counter Mode (GCM).

2. **Transformasi Domain Frekuensi dengan DCT**

   * Setiap frame video diubah ke domain frekuensi menggunakan blok DCT 8x8.

3. **Penyisipan dengan Quantization Index Modulation (QIM)**

   * Bit-bit payload disisipkan ke dalam koefisien AC hasil DCT dengan memodifikasi paritas kuantisasi.
   * Parameter `delta` dan jumlah koefisien AC yang digunakan dapat dikonfigurasi untuk mengatur kapasitas dan kualitas visual.

---

## ✨ Fitur Utama

* Enkripsi dan autentikasi gambar menggunakan SHA3 + ECC + AES-GCM
* Embedding data ke dalam video dengan QIM pada koefisien DCT
* Otomatisasi proses embedding dan ekstraksi
* Auto-generate file dummy jika input tidak tersedia
* Struktur modular dan extensible

---

## 🧪 Instalasi & Persiapan Lingkungan

### Opsi 1: Menggunakan Conda (Direkomendasikan)

1. **Clone Repository**

```bash
git clone https://github.com/erc-a/Secure-Video-Steganography-using-ECC-and-DCT.git
cd Secure-Video-Steganography-using-ECC-and-DCT
```

2. **Buat dan Aktifkan Environment Conda**

```bash
conda env create -f environment.yml
conda activate tubes_kripto
```

3. **Atau secara manual**

```bash
conda create -n tubes_kripto python=3.11
conda activate tubes_kripto
pip install numpy opencv-python pillow scipy cryptography
```

---

### Opsi 2: Menggunakan Virtual Environment (venv)

```bash
python -m venv env
# Aktifkan environment:
source env/bin/activate       # Linux/macOS
.\env\Scripts\activate        # Windows

pip install -r requirements.txt
```

---

### 📦 Library Utama

| Library         | Fungsi Utama                              |
| --------------- | ----------------------------------------- |
| `numpy`         | Operasi numerik dan manipulasi array      |
| `opencv-python` | Pemrosesan video dan frame capture        |
| `pillow`        | Pemrosesan dan konversi citra (PNG, dsb.) |
| `scipy`         | Transformasi DCT dan proses QIM           |
| `cryptography`  | AES-GCM, ECC (ECDH), SHA3                 |

---

## 🗂️ Struktur Folder

```
Secure-Video-Steganography-using-ECC-and-DCT/
├── app.py                  # Antarmuka aplikasi
├── config_and_setup.py    # Konfigurasi dan inisialisasi
├── embed_process.py       # Proses embedding utama
├── extract_process.py     # Proses ekstraksi utama
├── evaluation.py          # Evaluasi dan benchmarking kualitas
├── environment.yml        # Environment Conda
├── requirements.txt       # Requirements untuk pip
├── struktur.txt           # Deskripsi struktur
├── README.md              # Dokumentasi proyek
├── .gitignore
├── media/
│   ├── input/              # File input (cover video, secret image)
│   └── output/             # File output (stego video, extracted image)
```

---

## ▶️ Cara Menjalankan Program

1. \*\*Letakkan file input di \*\***`media/input/`**

   * `cover_1.mp4`, `cover_2.mp4` — video sebagai cover
   * `image32.png`, `image64.png` — gambar rahasia

   ⚠️ Jika file tidak ditemukan:

   * Program akan otomatis membuat `cover.mp4` (video dummy 640x480, 5 detik)
   * Program akan membuat gambar dummy grayscale 32x32

2. **Jalankan program utama**

```bash
python app.py
```

3. **Hasil akan muncul di ********`media/output/`********:**

   * `stego_video_final_output.avi` — video dengan payload disisipkan
   * `extracted_FINAL_secret_image.png` — hasil ekstraksi gambar rahasia

---

## 🎥 Catatan Codec

* Format output: `.avi` menggunakan codec **FFV1** (lossless, cross-platform)
* Pastikan sistem Anda mendukung FFV1 (Linux/macOS mungkin butuh konfigurasi tambahan OpenCV)

---

## 📌 Catatan Teknis

* Kunci ECC (publik dan privat) akan disimpan di folder root
* File akan di-overwrite jika dijalankan ulang
* SHA3-256 digunakan untuk integritas gambar setelah dekripsi

---

## 🧭 Lisensi

Proyek ini dibuat untuk keperluan **pembelajaran** dan tugas akademik.
Tidak disarankan untuk digunakan dalam aplikasi keamanan nyata tanpa audit menyeluruh.
