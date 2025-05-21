from PIL import Image
import numpy as np # Berguna untuk manipulasi array piksel yang efisien
import os

def gambar_ke_bitstream(path_gambar):
    """
    Membaca gambar, mengubahnya ke grayscale, dan mengonversinya menjadi bitstream.
    Juga mengembalikan dimensi gambar.
    """
    try:
        # 1. Buka gambar menggunakan Pillow
        img = Image.open(path_gambar)

        # 2. Ubah ke mode grayscale ('L')
        # Mode 'L' berarti luminance, 8-bit pixels, black and white.
        gray_img = img.convert('L')
        
        # 3. Dapatkan dimensi gambar
        lebar, tinggi = gray_img.size
        
        # 4. Dapatkan data piksel sebagai array NumPy untuk kemudahan
        pixel_data = np.array(gray_img) # Ini akan jadi array 2D (tinggi x lebar)
        
        # 5. Ubah setiap nilai piksel (0-255) menjadi string 8-bit
        bitstream_list = []
        for baris_piksel in pixel_data:
            for piksel_value in baris_piksel:
                # format(nilai, '08b') -> ubah angka jadi string biner 8-digit dengan padding nol di depan
                bitstream_list.append(format(piksel_value, '08b'))
        
        # 6. Gabungkan semua string bit menjadi satu bitstream panjang
        bitstream_gambar = "".join(bitstream_list)
        
        print(f"Gambar '{path_gambar}' ({lebar}x{tinggi}) berhasil diubah jadi bitstream ({len(bitstream_gambar)} bits).")
        return lebar, tinggi, bitstream_gambar

    except FileNotFoundError:
        print(f"Error: File gambar '{path_gambar}' tidak ditemukan.")
        return None, None, None
    except Exception as e:
        print(f"Error saat memproses gambar '{path_gambar}': {e}")
        return None, None, None

def bitstream_ke_gambar(bitstream_gambar, lebar, tinggi):
    """
    Mengubah bitstream kembali menjadi gambar grayscale berdasarkan dimensi yang diberikan.
    """
    try:
        # 1. Hitung total piksel dan panjang bitstream yang diharapkan
        total_piksel = lebar * tinggi
        panjang_bitstream_diharapkan = total_piksel * 8 # 8 bit per piksel grayscale

        if len(bitstream_gambar) != panjang_bitstream_diharapkan:
            print(f"Error: Panjang bitstream ({len(bitstream_gambar)}) tidak sesuai dengan dimensi yang diharapkan ({panjang_bitstream_diharapkan} untuk {lebar}x{tinggi}x8bit).")
            # Mungkin potong atau pad jika perlu, tapi untuk sekarang kita anggap error
            # Untuk robustness, bisa dipotong:
            # bitstream_gambar = bitstream_gambar[:panjang_bitstream_diharapkan]
            # if len(bitstream_gambar) < panjang_bitstream_diharapkan:
            #     print("Bitstream terlalu pendek setelah dipotong.")
            #     return None
            return None

        # 2. Ubah bitstream kembali menjadi nilai piksel
        pixel_values = []
        for i in range(0, len(bitstream_gambar), 8):
            byte_string = bitstream_gambar[i : i+8]
            pixel_values.append(int(byte_string, 2)) # Ubah string 8-bit jadi integer
            
        # 3. Bentuk kembali array piksel 2D (atau biarkan 1D dan biarkan Pillow yang atur)
        # Jika pixel_values adalah list 1D, kita bisa ubah jadi array NumPy dan reshape
        pixel_array_1d = np.array(pixel_values, dtype=np.uint8)
        pixel_array_2d = pixel_array_1d.reshape((tinggi, lebar))
        
        # 4. Buat objek gambar Pillow dari array piksel
        reconstructed_img = Image.fromarray(pixel_array_2d, mode='L') # Mode 'L' untuk grayscale
        
        print(f"Bitstream berhasil diubah kembali menjadi gambar ({lebar}x{tinggi}).")
        return reconstructed_img

    except Exception as e:
        print(f"Error saat mengubah bitstream menjadi gambar: {e}")
        return None

# Tambahkan ini ke file tahap4_helpers.py (atau file helpermu)

def buat_metadata_bitstream(lebar, tinggi, bits_untuk_dimensi=16):
    """
    Membuat bitstream metadata dari dimensi gambar.
    lebar: lebar gambar (integer)
    tinggi: tinggi gambar (integer)
    bits_untuk_dimensi: jumlah bit yang digunakan untuk merepresentasikan masing-masing dimensi
    """
    if lebar >= 2**bits_untuk_dimensi or tinggi >= 2**bits_untuk_dimensi or lebar < 0 or tinggi < 0:
        raise ValueError(f"Dimensi gambar (lebar={lebar}, tinggi={tinggi}) di luar jangkauan untuk {bits_untuk_dimensi}-bit.")
        
    # Ubah lebar menjadi string biner dengan panjang bits_untuk_dimensi
    bitstream_lebar = format(lebar, f'0{bits_untuk_dimensi}b')
    # Ubah tinggi menjadi string biner dengan panjang bits_untuk_dimensi
    bitstream_tinggi = format(tinggi, f'0{bits_untuk_dimensi}b')
    
    # Gabungkan bitstream lebar dan tinggi
    metadata_bitstream = bitstream_lebar + bitstream_tinggi
    
    # print(f"Metadata dibuat: Lebar={lebar} ({bitstream_lebar}), Tinggi={tinggi} ({bitstream_tinggi}). Total {len(metadata_bitstream)} bits.")
    return metadata_bitstream

def parse_metadata_bitstream(bitstream_metadata, bits_untuk_dimensi=16):
    """
    Mengurai bitstream metadata untuk mendapatkan dimensi gambar.
    bitstream_metadata: string bit yang berisi metadata (minimal panjangnya 2 * bits_untuk_dimensi)
    bits_untuk_dimensi: jumlah bit yang digunakan untuk merepresentasikan masing-masing dimensi
    """
    panjang_metadata_diharapkan = 2 * bits_untuk_dimensi
    if len(bitstream_metadata) < panjang_metadata_diharapkan:
        raise ValueError(f"Bitstream metadata terlalu pendek ({len(bitstream_metadata)} bits). Butuh minimal {panjang_metadata_diharapkan} bits.")
        
    # Ambil bit untuk lebar dan konversi ke integer
    bitstream_lebar = bitstream_metadata[0:bits_untuk_dimensi]
    lebar = int(bitstream_lebar, 2)
    
    # Ambil bit untuk tinggi dan konversi ke integer
    bitstream_tinggi = bitstream_metadata[bits_untuk_dimensi : panjang_metadata_diharapkan]
    tinggi = int(bitstream_tinggi, 2)
    
    # print(f"Metadata diurai: Lebar={lebar}, Tinggi={tinggi}.")
    return lebar, tinggi

# --- Modifikasi Contoh Penggunaan di akhir file tahap4_helpers.py ---
if __name__ == "__main__":
    # ... (kode dummy image dan tes gambar_ke_bitstream/bitstream_ke_gambar dari sebelumnya tetap ada) ...
    
    # (BAGIAN SEBELUMNYA)
    try:
        # Ini hanya contoh, idealnya path_gambar_rahasia didapat dari input atau argumen
        dummy_img = Image.new('L', (50, 30), color='white') # Gambar 50x30 piksel putih
        pixels = dummy_img.load()
        for i in range(50): # Lebar
            for j in range(30): # Tinggi
                pixels[i,j] = (i + j) % 256 # Isi dengan nilai piksel bervariasi
        dummy_img.save("dummy_secret_image_metadata_test.png")
        path_gambar_rahasia = "dummy_secret_image_metadata_test.png"
        print(f"Gambar dummy '{path_gambar_rahasia}' dibuat untuk tes metadata.")
    except Exception as e:
        print(f"Tidak bisa membuat gambar dummy, silakan siapkan file gambar sendiri: {e}")
        path_gambar_rahasia = "PATH_KE_GAMBAR_RAHASIAMU.png" # GANTI INI

    print("\n--- Tes gambar_ke_bitstream (lagi) ---")
    lebar_asli, tinggi_asli, bits_gambar = gambar_ke_bitstream(path_gambar_rahasia)

    if bits_gambar:
        print(f"Dimensi asli: {lebar_asli}x{tinggi_asli}")
        # print(f"Contoh awal bitstream gambar (64 bit pertama): {bits_gambar[:64]}...")
        
        # --- Tes Fungsi Metadata ---
        print("\n--- Tes buat_metadata_bitstream ---")
        try:
            metadata_bits = buat_metadata_bitstream(lebar_asli, tinggi_asli)
            print(f"Bitstream metadata (total {len(metadata_bits)} bits): {metadata_bits}")

            print("\n--- Tes parse_metadata_bitstream ---")
            parsed_lebar, parsed_tinggi = parse_metadata_bitstream(metadata_bits)
            print(f"Hasil parse metadata: Lebar={parsed_lebar}, Tinggi={parsed_tinggi}")

            if lebar_asli == parsed_lebar and tinggi_asli == parsed_tinggi:
                print("Verifikasi metadata BERHASIL: Dimensi asli dan hasil parse SAMA.")
            else:
                print("Verifikasi metadata GAGAL: Dimensi asli dan hasil parse BERBEDA.")
        except ValueError as ve:
            print(f"Error terkait metadata: {ve}")
        
        # --- Tes bitstream_ke_gambar (LAGI, SETELAH SEMUA TES LAINNYA) ---
        print("\n--- Tes bitstream_ke_gambar (lagi) ---")
        gambar_hasil_rekonstruksi = bitstream_ke_gambar(bits_gambar, lebar_asli, tinggi_asli)
        
        if gambar_hasil_rekonstruksi:
            gambar_hasil_rekonstruksi.show() 
            gambar_hasil_rekonstruksi.save("reconstructed_secret_image_metadata_test.png")
            print("Gambar hasil rekonstruksi disimpan sebagai 'reconstructed_secret_image_metadata_test.png'")
        else:
            print("Gagal merekonstruksi gambar.")
    else:
        print("Gagal mengubah gambar menjadi bitstream.")

def get_avi_path(base_path_or_full_path):
    """Mendapatkan path .avi dari nama dasar atau path lengkap."""
    base_name, _ = os.path.splitext(base_path_or_full_path)
    return base_name + ".avi"