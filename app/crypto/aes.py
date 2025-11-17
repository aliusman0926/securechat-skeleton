"""AES-128-ECB with PKCS#7 padding."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_aes(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-ECB.
    Returns ciphertext (no IV).
    """
    # PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return ct

def decrypt_aes(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-ECB.
    Returns plaintext (unpadded).
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    pt_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(pt_padded) + unpadder.finalize()
    return pt