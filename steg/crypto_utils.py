from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
import os

def bytes_ke_bitstream(data_bytes):
    return ''.join(format(byte, '08b') for byte in data_bytes)

def bitstream_ke_bytes(bitstream_data):
    sisa = len(bitstream_data) % 8
    if sisa: bitstream_data = bitstream_data[:-sisa]
    return bytes(int(bitstream_data[i:i+8], 2) for i in range(0, len(bitstream_data), 8))

def int_ke_bitstream(nilai_int, jumlah_bit):
    return format(nilai_int, f'0{jumlah_bit}b')

def bitstream_ke_int(bitstream_nilai):
    return int(bitstream_nilai, 2)

def enkripsi_aes_gcm(data_bytes, kunci):
    aesgcm = AESGCM(kunci)
    nonce = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(nonce, data_bytes, None)
    return ct_with_tag[:-16], nonce, ct_with_tag[-16:]

def dekripsi_aes_gcm(ct, kunci, nonce, tag):
    try:
        aesgcm = AESGCM(kunci)
        return aesgcm.decrypt(nonce, ct + tag, None)
    except InvalidTag:
        return None

def buat_pasangan_kunci_ecc():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()

def serialisasi_kunci_publik_ecc_compressed(pub):
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

def deserialisasi_kunci_publik_ecc_compressed(pub_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)

def buat_shared_secret_ecdh(priv, pub):
    return priv.exchange(ec.ECDH(), pub)

def derive_kunci_aes_dari_shared_secret(secret, salt):
    hkdf = HKDF(hashes.SHA256(), 32, salt, b'kunci aes untuk steganografi video')
    return hkdf.derive(secret)

def hitung_sha3_256(data):
    h = hashes.Hash(hashes.SHA3_256())
    h.update(data)
    return h.finalize()