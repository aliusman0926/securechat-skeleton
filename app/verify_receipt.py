# verify_receipt.py
import json
import hashlib
from app.crypto.sign import rsa_verify
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Load signed transcript
with open("logs/transcript_signed.json") as f:
    messages = json.load(f)

# Reconstruct EXACT signed bytes
transcript_bytes = []
for msg in messages:
    payload = json.dumps({
        "type": msg["type"],
        "content": msg["content"],
        "seqno": msg["seqno"],
        "ts": msg["ts"],
        "sig": msg["sig"]
    }, separators=(',', ':')).encode()
    transcript_bytes.append(payload)

computed_hash = hashlib.sha256(b''.join(transcript_bytes)).hexdigest()
print(f"Computed transcript hash: {computed_hash}")

# Load receipts (now have 'sig')
with open("logs/receipt_client.json") as f:
    client_receipt = json.load(f)
with open("logs/receipt_server.json") as f:
    server_receipt = json.load(f)

client_hash = client_receipt["transcript_hash"]
server_hash = server_receipt["transcript_hash"]

print(f"Client says: {client_hash}")
print(f"Server says: {server_hash}")

if client_hash == server_hash == computed_hash:
    print("All hashes match!")
    
    # Load certs
    with open("certs/client_cert.pem", "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())
    with open("certs/server_cert.pem", "rb") as f:
        server_cert = x509.load_pem_x509_certificate(f.read())

    # Verify
    if rsa_verify(client_cert.public_bytes(serialization.Encoding.PEM), computed_hash.encode(), client_receipt["sig"]):
        print("Client signature valid")
    else:
        print("Client signature INVALID")

    if rsa_verify(server_cert.public_bytes(serialization.Encoding.PEM), computed_hash.encode(), server_receipt["sig"]):
        print("Server signature valid")
    else:
        print("Server signature INVALID")
else:
    print("Hash mismatch!")