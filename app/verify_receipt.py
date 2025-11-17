# verify_receipt.py
import json
import hashlib
from app.crypto.sign import rsa_verify
from cryptography.hazmat.primitives import serialization

# Load signed messages from file
with open("logs/transcript_signed.json") as f:
    messages = json.load(f)

# Reconstruct exact byte transcript
transcript_bytes = []
for msg in messages:
    # Reconstruct exact JSON that was signed
    signed_json = json.dumps({
        "type": msg["type"],
        "content": msg["content"],
        "seqno": msg["seqno"],
        "ts": msg["ts"]
    }, separators=(',', ':')).encode()
    transcript_bytes.append(signed_json)

# Compute hash
computed_hash = hashlib.sha256(b''.join(transcript_bytes)).hexdigest()
print(f"Computed transcript hash: {computed_hash}")

# Load receipts
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
    
    # Verify signatures
    from app.crypto.pki import load_ca_cert
    from cryptography import x509
    client_cert = x509.load_pem_x509_certificate(open("certs/client_cert.pem", "rb").read())
    server_cert = x509.load_pem_x509_certificate(open("certs/server_cert.pem", "rb").read())
    
    client_pub = client_cert.public_key()
    server_pub = server_cert.public_key()
    
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