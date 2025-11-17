"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from app.common.utils import base64_encode, base64_decode

def rsa_sign(private_key_pem: bytes, data: bytes) -> str:
    """
    Sign data using RSA PKCS#1 v1.5 with SHA-256.
    Returns base64-encoded signature.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64_encode(signature)

def rsa_verify(cert_pem: bytes, data: bytes, signature_b64: str) -> bool:
    """
    Verify signature using RSA PKCS#1 v1.5 with SHA-256, extracting public key from cert PEM.
    Returns True if valid, False otherwise.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        public_key = cert.public_key()
        signature = base64_decode(signature_b64)
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False