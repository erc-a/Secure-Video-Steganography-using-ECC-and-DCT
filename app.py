import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import threading
import cv2  # Untuk PSNR
from PIL import Image  # Untuk menampilkan gambar hasil ekstraksi
from cryptography.hazmat.primitives import serialization  # Untuk load/save kunci ECC
import sys # Untuk redirect stdout

# --- IMPOR MODUL DARI FILE ANDA ---
try:
    import helpers as steg_helpers
    from config_and_setup import (
        buat_pasangan_kunci_ecc, 
        serialisasi_kunci_publik_ecc_compressed,
        # Fungsi lain akan dipanggil oleh embed_process atau extract_process
    )
    from embed_process import embed_gambar_ke_video_final
    from extract_process import ekstraksi_gambar_video_final
    from evaluation import psnr as hitung_psnr_eval, calc_ssim as hitung_ssim_eval
except ImportError as e:
    error_message = f"Modul tidak ditemukan: {e}"
    print(f"[ERROR IMPOR MODUL] {error_message}")
    try:
        root_err = tk.Tk(); root_err.withdraw()
        messagebox.showerror("Error Impor Modul Kritis", error_message); root_err.destroy()
    except: pass
    exit()
except Exception as e_general:
    error_message_general = f"Terjadi kesalahan saat impor modul: {e_general}"
    print(f"[ERROR IMPOR MODUL] {error_message_general}")
    try:
        root_err = tk.Tk(); root_err.withdraw()
        messagebox.showerror("Error Impor Kritis", error_message_general); root_err.destroy()
    except: pass
    exit()

class StdoutRedirector:
    """ Kelas untuk mengarahkan stdout ke widget Teks Tkinter. """
    def __init__(self, text_widget, gui_log_func):
        self.text_widget = text_widget
        self.gui_log_func = gui_log_func # Fungsi log GUI (misal self.log_pesan)

    def write(self, string):
        # Menulis ke widget teks GUI
        self.gui_log_func(string.strip(), "PROSES-INTI") # Hapus newline tambahan
        # Bisa juga ditulis ke stdout asli jika perlu
        # sys.__stdout__.write(string) 

    def flush(self):
        # Tkinter Text widget tidak butuh flush eksplisit biasanya
        pass

class AppSteganografiGUI:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("Aplikasi Steganografi Video - Kelompok X (DCT, SHA3, ECC, AES)")
        self.root.geometry("900x800") # Perbesar sedikit untuk log evaluasi

        # Variabel UI
        self.video_input_path_var = tk.StringVar()
        self.gambar_rahasia_path_var = tk.StringVar()
        self.video_output_base_path_var = tk.StringVar()
        self.gambar_ekstraksi_output_path_var = tk.StringVar()
        self.kunci_publik_penerima_path_var = tk.StringVar()
        self.kunci_privat_penerima_path_var = tk.StringVar()
        
        self.delta_qim_var = tk.IntVar(value=20)
        self.num_ac_coeffs_var = tk.IntVar(value=10)
        self.mode_var = tk.StringVar(value="embed")

        self.base_dir = os.getcwd()
        self.input_dir = os.path.join(self.base_dir, "media", "input")
        self.output_dir = os.path.join(self.base_dir, "media", "output")
        os.makedirs(self.input_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)

        self.kunci_publik_penerima_path_var.set(os.path.join(self.base_dir, "bob_public_key.pem"))
        self.kunci_privat_penerima_path_var.set(os.path.join(self.base_dir, "bob_private_key.pem"))
        self.video_output_base_path_var.set(os.path.join(self.output_dir, "stego_video_gui_output"))
        self.gambar_ekstraksi_output_path_var.set(os.path.join(self.output_dir, "extracted_image_gui.png"))

        self.buat_ui_utama()
        
        # Inisialisasi stdout redirector
        self.stdout_redirector = StdoutRedirector(self.log_text, self.log_pesan)


    def log_pesan(self, pesan, type="INFO"):
        self.log_text.config(state=tk.NORMAL)
        # Hapus newline ganda jika pesan sudah mengandung newline dari print
        pesan_cleaned = pesan.strip('\n')
        if pesan_cleaned: # Hanya insert jika ada pesan setelah dibersihkan
            self.log_text.insert(tk.END, f"[{type}] {pesan_cleaned}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.root.update_idletasks()

    def pilih_file_dialog(self, title, filetypes, path_variable, mode="open"):
        initial_dir_to_use = self.input_dir
        if mode == "save": initial_dir_to_use = self.output_dir
        
        filepath = ""
        if mode == "open":
            filepath = filedialog.askopenfilename(title=title, filetypes=filetypes, initialdir=initial_dir_to_use)
        elif mode == "save":
            def_ext = filetypes[0][1].replace("*","") if filetypes and filetypes[0][1] else ".txt"
            filepath = filedialog.asksaveasfilename(title=title, defaultextension=def_ext, filetypes=filetypes, initialdir=initial_dir_to_use)
        
        if filepath:
            path_variable.set(filepath)
            self.log_pesan(f"Path diatur: {os.path.basename(filepath)} -> {filepath}", "CONFIG")

    def update_ui_visibility(self):
        mode = self.mode_var.get()
        # self.log_pesan(f"Mode diubah ke: {mode.upper()}", "CONFIG") # Log ini bisa jadi terlalu sering

        is_embed = mode == "embed"
        is_extract = mode == "extract"
        is_genkey = mode == "genkey"

        def set_visibility(widget_tuple_list, show, start_row):
            current_row = start_row
            for lbl, entry, btn in widget_tuple_list:
                if show:
                    lbl.grid(row=current_row, column=0, sticky=tk.W, padx=5, pady=3)
                    entry.grid(row=current_row, column=1, sticky=tk.EW, padx=5, pady=3)
                    btn.grid(row=current_row, column=2, padx=5, pady=3)
                else:
                    lbl.grid_remove(); entry.grid_remove(); btn.grid_remove()
                current_row +=1
            return current_row # Kembalikan baris berikutnya yang tersedia

        # Sembunyikan semua dulu
        for widget_list in [self.embed_specific_widgets, self.extract_specific_widgets, self.genkey_specific_widgets]:
            set_visibility(widget_list, False, 0) # Argumen row tidak terlalu penting saat hide

        self.param_frame.grid_remove()
        
        # Tampilkan yang relevan
        r_next = 1 # Baris setelah Video Input
        if is_embed:
            set_visibility(self.embed_specific_widgets, True, r_next)
            self.param_frame.grid(row=2, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=5)
            self.btn_jalankan.config(text="Mulai Embedding")
            self.lbl_video_input.config(text="Video Input (Cover):")
        elif is_extract:
            set_visibility(self.extract_specific_widgets, True, r_next)
            self.param_frame.grid(row=2, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=5)
            self.btn_jalankan.config(text="Mulai Ekstraksi")
            self.lbl_video_input.config(text="Video Input (Stego):")
        elif is_genkey:
            set_visibility(self.genkey_specific_widgets, True, r_next)
            self.btn_jalankan.config(text="Buat Kunci ECC Penerima")
        
        self.btn_jalankan.grid(row=3, column=0, columnspan=3, pady=10)


    def buat_ui_utama(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)
        main_frame.columnconfigure(1, weight=1)

        mode_frame = ttk.LabelFrame(main_frame, text="Mode Operasi", padding="10")
        mode_frame.grid(row=0, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=5)
        modes = [("Embed Gambar", "embed"), ("Ekstrak Gambar", "extract"), ("Buat Kunci ECC", "genkey")]
        for i, (text, mode_val) in enumerate(modes):
            ttk.Radiobutton(mode_frame, text=text, variable=self.mode_var, value=mode_val, command=self.update_ui_visibility).pack(side=tk.LEFT, padx=10, pady=5)
        for text, mode_val in modes:
            files_keys_frame = ttk.LabelFrame(main_frame, text="File & Kunci", padding="10")
            files_keys_frame.grid(row=1, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=5)
            files_keys_frame.columnconfigure(1, weight=1) 
            r = 0 
            self.lbl_video_input = ttk.Label(files_keys_frame, text="Video Input (Cover):")
            # Widget video input selalu ada, jadi di-grid langsung
            self.lbl_video_input.grid(row=r, column=0, sticky=tk.W, padx=5, pady=3)
            ttk.Entry(files_keys_frame, textvariable=self.video_input_path_var, width=60).grid(row=r, column=1, sticky=tk.EW, padx=5, pady=3)
            ttk.Button(files_keys_frame, text="Pilih...", command=lambda: self.pilih_file_dialog("Pilih Video Input", [("Video files", "*.mp4 *.avi"), ("All files", "*.*")], self.video_input_path_var)).grid(row=r, column=2, padx=5, pady=3)
            # r_next_input = r + 1 # Tidak perlu lagi

            self.embed_specific_widgets = []
            self.extract_specific_widgets = []
            self.genkey_specific_widgets = []

            # Embed widgets
            self.lbl_gambar_rahasia = ttk.Label(files_keys_frame, text="Gambar Rahasia:")
            self.entry_gambar_rahasia = ttk.Entry(files_keys_frame, textvariable=self.gambar_rahasia_path_var, width=60)
            self.btn_gambar_rahasia = ttk.Button(files_keys_frame, text="Pilih...", command=lambda: self.pilih_file_dialog("Pilih Gambar Rahasia", [("Image files", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")], self.gambar_rahasia_path_var))
            self.embed_specific_widgets.append((self.lbl_gambar_rahasia, self.entry_gambar_rahasia, self.btn_gambar_rahasia))

            self.lbl_video_output = ttk.Label(files_keys_frame, text="Video Output Stego (Nama Dasar):")
            self.entry_video_output = ttk.Entry(files_keys_frame, textvariable=self.video_output_base_path_var, width=60)
            self.btn_video_output = ttk.Button(files_keys_frame, text="Simpan Sebagai...", command=lambda: self.pilih_file_dialog("Simpan Video Stego", [("AVI Video", "*.avi")], self.video_output_base_path_var, mode="save"))
            self.embed_specific_widgets.append((self.lbl_video_output, self.entry_video_output, self.btn_video_output))

            self.lbl_kunci_publik_embed = ttk.Label(files_keys_frame, text="Kunci Publik Penerima (.pem):")
            self.entry_kunci_publik_embed = ttk.Entry(files_keys_frame, textvariable=self.kunci_publik_penerima_path_var, width=60)
            self.btn_kunci_publik_embed = ttk.Button(files_keys_frame, text="Pilih...", command=lambda: self.pilih_file_dialog("Pilih Kunci Publik Penerima", [("PEM files", "*.pem")], self.kunci_publik_penerima_path_var))
            self.embed_specific_widgets.append((self.lbl_kunci_publik_embed, self.entry_kunci_publik_embed, self.btn_kunci_publik_embed))

            # Extract widgets
            self.lbl_gambar_ekstraksi = ttk.Label(files_keys_frame, text="Gambar Hasil Ekstraksi:")
            self.entry_gambar_ekstraksi = ttk.Entry(files_keys_frame, textvariable=self.gambar_ekstraksi_output_path_var, width=60)
            self.btn_gambar_ekstraksi = ttk.Button(files_keys_frame, text="Simpan Sebagai...", command=lambda: self.pilih_file_dialog("Simpan Gambar Ekstraksi", [("PNG Image", "*.png")], self.gambar_ekstraksi_output_path_var, mode="save"))
            self.extract_specific_widgets.append((self.lbl_gambar_ekstraksi, self.entry_gambar_ekstraksi, self.btn_gambar_ekstraksi))
            
            self.lbl_kunci_privat_extract = ttk.Label(files_keys_frame, text="Kunci Privat Penerima (.pem):")
            self.entry_kunci_privat_extract = ttk.Entry(files_keys_frame, textvariable=self.kunci_privat_penerima_path_var, width=60)
            self.btn_kunci_privat_extract = ttk.Button(files_keys_frame, text="Pilih...", command=lambda: self.pilih_file_dialog("Pilih Kunci Privat Penerima", [("PEM files", "*.pem")], self.kunci_privat_penerima_path_var))
            self.extract_specific_widgets.append((self.lbl_kunci_privat_extract, self.entry_kunci_privat_extract, self.btn_kunci_privat_extract))
            
            # GenKey widgets
            self.lbl_kunci_publik_gen = ttk.Label(files_keys_frame, text="Simpan Kunci Publik Baru Ke:")
            self.entry_kunci_publik_gen = ttk.Entry(files_keys_frame, textvariable=self.kunci_publik_penerima_path_var, width=60)
            self.btn_kunci_publik_gen = ttk.Button(files_keys_frame, text="Simpan Sebagai...", command=lambda: self.pilih_file_dialog("Simpan Kunci Publik Baru", [("PEM files", "*.pem")], self.kunci_publik_penerima_path_var, mode="save"))
            self.genkey_specific_widgets.append((self.lbl_kunci_publik_gen, self.entry_kunci_publik_gen, self.btn_kunci_publik_gen))

            self.lbl_kunci_privat_gen = ttk.Label(files_keys_frame, text="Simpan Kunci Privat Baru Ke:")
            self.entry_kunci_privat_gen = ttk.Entry(files_keys_frame, textvariable=self.kunci_privat_penerima_path_var, width=60)
            self.btn_kunci_privat_gen = ttk.Button(files_keys_frame, text="Simpan Sebagai...", command=lambda: self.pilih_file_dialog("Simpan Kunci Privat Baru", [("PEM files", "*.pem")], self.kunci_privat_penerima_path_var, mode="save"))
            self.genkey_specific_widgets.append((self.lbl_kunci_privat_gen, self.entry_kunci_privat_gen, self.btn_kunci_privat_gen))
        
        # Atur grid untuk semua widget spesifik mode (awalnya disembunyikan)
        for widget_list in [self.embed_specific_widgets, self.extract_specific_widgets, self.genkey_specific_widgets]:
            for lbl, entry, btn in widget_list:
                lbl.grid_remove(); entry.grid_remove(); btn.grid_remove()


        self.param_frame = ttk.LabelFrame(main_frame, text="Parameter Steganografi", padding="10")
        # Posisi grid diatur oleh update_ui_visibility
        ttk.Label(self.param_frame, text="DELTA QIM:").pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Spinbox(self.param_frame, from_=1, to=100, textvariable=self.delta_qim_var, width=5).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Label(self.param_frame, text="Koefisien AC per Blok:").pack(side=tk.LEFT, padx=15, pady=5)
        ttk.Spinbox(self.param_frame, from_=1, to=63, textvariable=self.num_ac_coeffs_var, width=5).pack(side=tk.LEFT, padx=5, pady=5)
        self.param_steg_widgets = [self.param_frame]
        self.param_frame.grid_remove() # Sembunyikan awal

        action_frame = ttk.Frame(main_frame, padding="10")
        action_frame.grid(row=3, column=0, columnspan=3, pady=10) 
        self.btn_jalankan = ttk.Button(action_frame, text="Jalankan Proses", command=self.jalankan_proses_utama_thread)
        self.btn_jalankan.grid_remove() # Sembunyikan awal, diatur oleh update_ui_visibility

        log_frame = ttk.LabelFrame(main_frame, text="Log Proses", padding="10")
        log_frame.grid(row=4, column=0, columnspan=3, sticky=tk.NSEW, padx=5, pady=5) 
        main_frame.rowconfigure(4, weight=1) 
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, state=tk.DISABLED, font=("Consolas", 9))
        self.log_text.pack(expand=True, fill=tk.BOTH)

        self.update_ui_visibility() # Atur visibilitas awal yang benar

    def jalankan_proses_utama_thread(self):
        self.btn_jalankan.config(state=tk.DISABLED)
        self.log_text.config(state=tk.NORMAL); self.log_text.delete(1.0, tk.END); self.log_text.config(state=tk.DISABLED)
        mode = self.mode_var.get()
        delta = self.delta_qim_var.get()
        coeffs = self.num_ac_coeffs_var.get()

        # Redirect stdout ke log_text selama proses background
        original_stdout = sys.stdout
        sys.stdout = self.stdout_redirector

        if mode == "embed":
            threading.Thread(target=self.proses_embed_background_gui, args=(delta, coeffs, original_stdout), daemon=True).start()
        elif mode == "extract":
            threading.Thread(target=self.proses_ekstrak_background_gui, args=(delta, coeffs, original_stdout), daemon=True).start()
        elif mode == "genkey":
            threading.Thread(target=self.proses_genkey_background_gui, args=(original_stdout,), daemon=True).start()
        else: 
            self.btn_jalankan.config(state=tk.NORMAL)
            sys.stdout = original_stdout # Kembalikan stdout

    def proses_selesai_gui(self, original_stdout):
        """Dipanggil setelah proses background selesai."""
        sys.stdout = original_stdout # Kembalikan stdout
        self.btn_jalankan.config(state=tk.NORMAL)
        self.log_pesan("Proses selesai.", "STATUS")

    def proses_genkey_background_gui(self, original_stdout):
        self.log_pesan("Memulai pembuatan kunci ECC...", "PROSES")
        try:
            pub_key_path = self.kunci_publik_penerima_path_var.get()
            priv_key_path = self.kunci_privat_penerima_path_var.get()
            if not pub_key_path or not priv_key_path:
                self.log_pesan("Path untuk kunci publik dan privat harus ditentukan.", "ERROR")
                messagebox.showerror("Error", "Harap tentukan path untuk menyimpan kunci.")
                self.proses_selesai_gui(original_stdout); return

            abs_priv_key_path = os.path.abspath(priv_key_path)
            abs_pub_key_path = os.path.abspath(pub_key_path)
            if os.path.exists(abs_priv_key_path) or os.path.exists(abs_pub_key_path):
                if not messagebox.askyesno("Konfirmasi", f"File kunci '{os.path.basename(abs_priv_key_path)}' atau '{os.path.basename(abs_pub_key_path)}' sudah ada. Timpa?"):
                    self.log_pesan("Pembuatan kunci dibatalkan.", "INFO"); self.proses_selesai_gui(original_stdout); return
            
            private_key, public_key = buat_pasangan_kunci_ecc() 
            with open(abs_priv_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(abs_pub_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            self.log_pesan(f"Kunci ECC berhasil dibuat:\n  Privat: {abs_priv_key_path}\n  Publik: {abs_pub_key_path}", "SUKSES")
            messagebox.showinfo("Sukses", f"Kunci ECC berhasil dibuat:\nPrivat: {abs_priv_key_path}\nPublik: {abs_pub_key_path}")
        except Exception as e:
            self.log_pesan(f"Error buat kunci: {e}", "ERROR"); messagebox.showerror("Error", f"Gagal membuat kunci: {e}")
        finally: 
            self.proses_selesai_gui(original_stdout)

    def proses_embed_background_gui(self, delta, coeffs, original_stdout):
        self.log_pesan("Memulai embedding...", "PROSES")
        video_in = self.video_input_path_var.get()
        secret_img = self.gambar_rahasia_path_var.get()
        video_out_base = self.video_output_base_path_var.get()
        receiver_pub_key_path = self.kunci_publik_penerima_path_var.get()
        
        try:
            self.log_pesan(f"Video Input: {video_in}", "DETAIL")
            self.log_pesan(f"Gambar Rahasia: {secret_img}", "DETAIL")
            self.log_pesan(f"Output Video Base: {video_out_base}", "DETAIL")
            self.log_pesan(f"Kunci Publik Penerima: {receiver_pub_key_path}", "DETAIL")
            self.log_pesan(f"DELTA: {delta}, Koefisien AC: {coeffs}", "DETAIL")

            with open(receiver_pub_key_path, "rb") as f:
                bob_public_ecc_obj = serialization.load_pem_public_key(f.read())
            bob_public_key_bytes_compressed = serialisasi_kunci_publik_ecc_compressed(bob_public_ecc_obj)
            self.log_pesan("Kunci publik penerima dimuat.", "INFO")
            
            self.log_pesan("Memanggil fungsi embedding inti...", "PROSES")
            berhasil, first_orig_gray, first_stego_gray = embed_gambar_ke_video_final(
                video_in, secret_img, video_out_base, delta, coeffs, bob_public_key_bytes_compressed
            )

            if berhasil:
                actual_stego_path = steg_helpers.get_avi_path(video_out_base)
                self.log_pesan(f"EMBEDDING BERHASIL! Output: {actual_stego_path}", "SUKSES")
                if first_orig_gray is not None and first_stego_gray is not None:
                    try:
                        psnr = cv2.PSNR(first_orig_gray, first_stego_gray)
                        self.log_pesan(f"PSNR Frame Pertama (Grayscale): {psnr:.2f} dB", "INFO")
                    except Exception as e_psnr:
                        self.log_pesan(f"Tidak bisa hitung PSNR: {e_psnr}", "WARNING")
                messagebox.showinfo("Sukses", f"Embedding berhasil! Video: {actual_stego_path}")
            else:
                self.log_pesan("EMBEDDING GAGAL.", "ERROR"); messagebox.showerror("Gagal", "Embedding gagal.")
        except FileNotFoundError as fnf_error:
            self.log_pesan(f"Error File Tidak Ditemukan: {fnf_error}", "ERROR")
            messagebox.showerror("Error File", f"File tidak ditemukan: {fnf_error}")
        except Exception as e:
            self.log_pesan(f"Error embedding: {e}", "ERROR"); messagebox.showerror("Error", f"Error: {e}")
        finally: 
            self.proses_selesai_gui(original_stdout)

    def proses_ekstrak_background_gui(self, delta, coeffs, original_stdout):
        self.log_pesan("Memulai ekstraksi...", "PROSES")
        stego_video = self.video_input_path_var.get() 
        extracted_img_out = self.gambar_ekstraksi_output_path_var.get()
        receiver_priv_key_path = self.kunci_privat_penerima_path_var.get()
        
        try:
            self.log_pesan(f"Stego Video: {stego_video}", "INFO") 
            self.log_pesan(f"Output Gambar: {extracted_img_out}", "INFO")
            self.log_pesan(f"Kunci Privat Penerima: {receiver_priv_key_path}", "INFO")
            self.log_pesan(f"DELTA: {delta}, Koefisien AC: {coeffs}", "INFO")

            with open(receiver_priv_key_path, "rb") as f:
                bob_private_ecc = serialization.load_pem_private_key(f.read(), password=None)
            self.log_pesan("Kunci privat penerima dimuat.", "INFO")
            
            self.log_pesan("Memanggil fungsi ekstraksi inti...", "PROSES")
            berhasil = ekstraksi_gambar_video_final(
                stego_video, extracted_img_out, delta, coeffs, bob_private_ecc
            )

            if berhasil:
                self.log_pesan(f"EKSTRAKSI BERHASIL! Gambar: {extracted_img_out}", "SUKSES")
                messagebox.showinfo("Sukses", f"Ekstraksi berhasil! Gambar: {extracted_img_out}")
                try: 
                    img = Image.open(extracted_img_out)
                    img.show()
                except Exception as e_show: self.log_pesan(f"Tidak bisa tampilkan gambar: {e_show}", "WARNING")
                
                # --- Integrasi Evaluasi ---
                self.log_pesan("Memulai evaluasi gambar hasil ekstraksi...", "PROSES")
                # Asumsi gambar asli ada di self.gambar_rahasia_path_var.get() jika mode embed pernah dijalankan
                # atau pengguna harus memilihnya lagi. Untuk simplifikasi, kita coba path dari embed.
                original_secret_image_for_eval = self.gambar_rahasia_path_var.get() # Ini mungkin kosong jika GUI baru dibuka di mode extract
                if not original_secret_image_for_eval and os.path.exists(os.path.join(self.input_dir, "ini_adalah_rahasia_grayscale.png")):
                    original_secret_image_for_eval = os.path.join(self.input_dir, "ini_adalah_rahasia_grayscale.png")
                
                if os.path.exists(original_secret_image_for_eval) and os.path.exists(extracted_img_out):
                    self.log_pesan(f"Membandingkan '{original_secret_image_for_eval}' dengan '{extracted_img_out}'", "INFO")
                    
                    # Panggil fungsi dari evaluation.py (jika sudah diimpor sebagai 'eval_mod')
                    # Untuk sekarang, kita panggil fungsi PSNR dan SSIM langsung jika ada
                    try:
                        img_asli_eval = cv2.imread(original_secret_image_for_eval, cv2.IMREAD_GRAYSCALE)
                        img_ekstrak_eval = cv2.imread(extracted_img_out, cv2.IMREAD_GRAYSCALE)

                        if img_asli_eval is not None and img_ekstrak_eval is not None:
                            if img_asli_eval.shape != img_ekstrak_eval.shape:
                                self.log_pesan("Ukuran gambar asli dan ekstraksi berbeda, resize untuk evaluasi.", "WARNING")
                                img_ekstrak_eval = cv2.resize(img_ekstrak_eval, (img_asli_eval.shape[1], img_asli_eval.shape[0]))

                            psnr_img_val = hitung_psnr_eval(img_asli_eval, img_ekstrak_eval) # Dari evaluation.py
                            ssim_img_val = hitung_ssim_eval(img_asli_eval, img_ekstrak_eval) # Dari evaluation.py
                            
                            self.log_pesan(f"  Evaluasi Gambar Ekstraksi:", "HASIL")
                            self.log_pesan(f"    PSNR: {psnr_img_val:.2f} dB", "HASIL")
                            self.log_pesan(f"    SSIM: {ssim_img_val:.4f}", "HASIL")
                            if psnr_img_val == float('inf') or psnr_img_val > 40 : # Dianggap sangat baik / identik
                                self.log_pesan("    Kualitas Ekstraksi: SEMPURNA / SANGAT BAIK", "HASIL")
                            elif psnr_img_val > 30:
                                self.log_pesan("    Kualitas Ekstraksi: BAIK", "HASIL")
                            else:
                                self.log_pesan("    Kualitas Ekstraksi: KURANG", "HASIL")
                        else:
                            self.log_pesan("Tidak bisa membaca gambar untuk evaluasi.", "ERROR")
                    except Exception as e_eval:
                        self.log_pesan(f"Error saat evaluasi gambar: {e_eval}", "ERROR")
                else:
                    self.log_pesan("Tidak bisa melakukan evaluasi gambar: file asli atau ekstraksi tidak ditemukan.", "WARNING")
            else:
                self.log_pesan("EKSTRAKSI GAGAL.", "ERROR"); messagebox.showerror("Gagal", "Ekstraksi gagal.")
        except FileNotFoundError as fnf_error:
            self.log_pesan(f"Error File Tidak Ditemukan: {fnf_error}", "ERROR")
            messagebox.showerror("Error File", f"File tidak ditemukan: {fnf_error}")
        except Exception as e:
            self.log_pesan(f"Error tidak terduga saat ekstraksi: {e}", "ERROR")
            messagebox.showerror("Error Ekstraksi", f"Terjadi kesalahan: {e}")
        finally: 
            self.proses_selesai_gui(original_stdout)


if __name__ == '__main__':
    module_files_to_check = ["helpers.py", "config_and_setup.py", "embed_process.py", "extract_process.py", "evaluation.py"]
    missing_files_found = [f for f in module_files_to_check if not os.path.exists(f)]
    
    root_tk_main = tk.Tk() 
    if missing_files_found:
        root_tk_main.withdraw() 
        messagebox.showerror("Error Modul Kritis", f"File modul berikut tidak ditemukan: {', '.join(missing_files_found)}\nAplikasi tidak bisa berjalan.")
        root_tk_main.destroy()
        exit()

    app_gui = AppSteganografiGUI(root_tk_main)
    root_tk_main.mainloop()
