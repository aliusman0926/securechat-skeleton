"""Classic Diffie-Hellman key exchange + key derivation."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
import os

# RFC 3526 2048-bit MODP Group 14
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
G = 2

parameters = dh.DHParameterNumbers(P, G).parameters()

def generate_dh_keypair() -> tuple[bytes, bytes]:
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def derive_shared_secret(private_pem: bytes, peer_public_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    peer_public_key = serialization.load_pem_public_key(peer_public_pem)
    shared = private_key.exchange(peer_public_key)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared)
    return digest.finalize()[:16]

def send_dh_pub(conn, pub_pem: bytes):
    length = len(pub_pem).to_bytes(4, 'big')
    conn.sendall(length + pub_pem)

def recv_dh_pub(conn) -> bytes:
    length = int.from_bytes(conn.recv(4), 'big')
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Closed")
        data += chunk
    return data