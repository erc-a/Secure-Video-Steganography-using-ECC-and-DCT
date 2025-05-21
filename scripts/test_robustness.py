import os
import subprocess
import cv2
import numpy as np
from datetime import datetime
import sys

# Fix path for relative imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from steg.helpers import get_avi_path
from steg.crypto_utils import serialisasi_kunci_publik_ecc_compressed, buat_pasangan_kunci_ecc
from main import extract_wrapper  # assumed to be compatible for reuse

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'results'))
os.makedirs(OUTPUT_DIR, exist_ok=True)

STEGO_VIDEO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'media', 'output', 'stego_video_final_output.avi'))
PRIVATE_KEY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'keys', 'bob_private_key.pem'))
DELTA = 20
AC_COEFFS = 10

variants = {
    "reencoded": "-c:v libx264 -crf 28 -preset slow",
    "cropped": "-vf crop=iw-100:ih-100",
    "resized": "-vf scale=320:240",
    "noised":  "-vf noise=alls=20:allf=t+u"
}

report_txt = []
report_md = [f"# Robustness Test Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"]

def ffmpeg_transform(input_path, output_path, ffmpeg_args):
    cmd = f"ffmpeg -y -i \"{input_path}\" {ffmpeg_args} \"{output_path}\""
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def test_variant(name, args):
    print(f"[TEST] {name.upper()}...")
    mod_path = os.path.join(OUTPUT_DIR, f"stego_{name}.avi")
    img_out_path = os.path.join(OUTPUT_DIR, f"extracted_{name}.png")

    ffmpeg_transform(STEGO_VIDEO, mod_path, args)
    try:
        result = extract_wrapper(mod_path, img_out_path, PRIVATE_KEY_PATH)
        if result is None:
            raise ValueError("Extracted result is None")

        success, orig, stego = result
        if success and orig is not None and stego is not None:
            psnr = cv2.PSNR(orig, stego)
            result_str = f"{name:<10} | PSNR: {psnr:.2f} dB | Status: PASS"
            report_md.append(f"- **{name.capitalize()}**: `{psnr:.2f} dB` ✅")
        else:
            result_str = f"{name:<10} | PSNR: N/A         | Status: FAIL"
            report_md.append(f"- **{name.capitalize()}**: `FAILED` ❌")
    except Exception as e:
        result_str = f"{name:<10} | Error: {str(e)}"
        report_md.append(f"- **{name.capitalize()}**: `Error: {str(e)}` ❌")

    print(result_str)
    report_txt.append(result_str)

def run_all():
    for name, args in variants.items():
        test_variant(name, args)

    # Save report
    with open(os.path.join(OUTPUT_DIR, "robustness_report.txt"), 'w') as f:
        f.write("Robustness Test Report\n=======================\n\n")
        f.write("\n".join(report_txt))

    with open(os.path.join(OUTPUT_DIR, "robustness_report.md"), 'w', encoding='utf-8') as f:
        f.write("\n".join(report_md))

    print("\n[FINISHED] Laporan tersimpan di results/robustness_report.txt & .md")

if __name__ == '__main__':
    run_all()
