import cv2, numpy as np
from scipy.fftpack import dct, idct

def proses_frame_qim_dct(frame_bgr, mode, delta, bit_payload_segment=None, num_ac_coeffs_to_use=63):
    gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY) if frame_bgr.ndim == 3 else frame_bgr.copy()
    h, w = gray.shape
    float_img = np.float32(gray)
    out_img = float_img.copy()
    block = 8
    bits_out = []
    idx = 0
    max_bits = len(bit_payload_segment) if (mode == 'embed' and bit_payload_segment) else 0

    for r in range(0, h, block):
        if mode == 'embed' and idx >= max_bits:
            break
        for c in range(0, w, block):
            if mode == 'embed' and idx >= max_bits:
                break
            d = dct(dct(float_img[r:r+block, c:c+block], axis=0, norm='ortho'), axis=1, norm='ortho')
            flat = d.flatten()
            mod = flat.copy()
            for i in range(min(num_ac_coeffs_to_use, len(flat) - 1)):
                ci = i + 1
                val = flat[ci]
                if delta <= 0:
                    if mode == 'extract':
                        bits_out.append('0')
                    continue
                if mode == 'embed':
                    if idx >= max_bits:
                        break
                    bit = int(bit_payload_segment[idx])
                    qidx = int(round(val / delta))
                    if qidx % 2 != bit:
                        qidx += 1 if bit == 1 else -1
                    mod[ci] = qidx * delta
                    idx += 1
                elif mode == 'extract':
                    bits_out.append(str(int(round(val / delta)) % 2))
            if mode == 'embed':
                idct_blk = idct(idct(mod.reshape((block, block)), axis=0, norm='ortho'), axis=1, norm='ortho')
                out_img[r:r+block, c:c+block] = idct_blk

    return (gray, np.uint8(np.clip(out_img, 0, 255)), idx) if mode == 'embed' else ''.join(bits_out)
