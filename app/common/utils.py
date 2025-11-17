"""Utility helpers: base64, timestamps, SHA-256."""

import base64
import hashlib
import time
import secrets

def now_ms() -> int:
    """Return current time in milliseconds since epoch (UTC)."""
    return int(time.time() * 1000)

def sha256_hex(data: bytes) -> str:
    """Return hex-encoded SHA-256 hash of input bytes."""
    return hashlib.sha256(data).hexdigest()

def base64_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string (no padding)."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def base64_decode(s: str) -> bytes:
    """Decode URL-safe base64 string to bytes (pad if needed)."""
    s = s + '=' * (-len(s) % 4)  # Add padding
    return base64.urlsafe_b64decode(s)

def random_nonce() -> str:
    """Generate 16-byte cryptographically secure nonce, base64-encoded."""
    return base64_encode(secrets.token_bytes(16))

def send_binary(sock, data: bytes):
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

def recv_binary(sock) -> bytes:
    length_bytes = b""
    print("Receiving binary data...")
    while len(length_bytes) < 4:
        chunk = sock.recv(4 - len(length_bytes))
        if not chunk:
            raise ConnectionError("Connection closed")
        length_bytes += chunk
    length = int.from_bytes(length_bytes, 'big')
    data = b""
    print(f"Expecting {length} bytes...")
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    print("Binary data received.")
    return data