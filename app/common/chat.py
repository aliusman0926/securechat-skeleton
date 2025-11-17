# app/common/chat.py
import json
import time
from app.common.utils import now_ms, base64_encode
from app.crypto.sign import rsa_sign
import hashlib

def build_chat_message(content: str, seqno: int, private_pem: bytes) -> dict:
    """Return a dict ready to be JSON-serialised (sig added later)."""
    return {
        "type": "msg",
        "content": content,
        "seqno": seqno,
        "ts": now_ms()
    }

def sign_chat_message(msg_dict: dict, private_pem: bytes) -> str:
    """Sign the JSON bytes of the dict *without* the sig field."""
    payload = json.dumps(msg_dict, separators=(',', ':')).encode()
    return rsa_sign(private_pem, payload)

def compute_transcript_hash(transcript: list[bytes]) -> str:
    h = hashlib.sha256()
    for msg in transcript:
        h.update(msg)
    return h.hexdigest()

def build_receipt(transcript_hash: str, private_pem: bytes) -> dict:
    msg = {
        "type": "receipt",
        "transcript_hash": transcript_hash
    }
    msg["sig"] = rsa_sign(private_pem, transcript_hash.encode())
    return msg