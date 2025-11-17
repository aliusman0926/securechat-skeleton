"""Client workflow — plain TCP, no TLS."""

import socket
import json
import os
import hashlib
import secrets
from app.common.protocol import HelloMessage, RegisterMessage, LoginMessage, parse_control_message
from app.common.utils import random_nonce, base64_encode, base64_decode, send_binary, recv_binary
from app.crypto.pki import verify_certificate_chain
from app.crypto.dh import generate_dh_keypair, derive_shared_secret
from app.crypto.aes import encrypt_aes, decrypt_aes
import sys

HOST = '127.0.0.1'
PORT = 4444
CERTS_DIR = 'certs'

def load_cert(path: str) -> str:
    with open(path, 'r') as f:
        return f.read()

def recv_text_line(s):
    data = b""
    while not data.endswith(b'\n'):
        chunk = s.recv(1)
        if not chunk:
            raise ConnectionError("Closed")
        data += chunk
    return data.strip()

def main():
    client_cert = load_cert(os.path.join(CERTS_DIR, 'client_cert.pem'))
    client_key_path = os.path.join(CERTS_DIR, 'client_key.pem')
    with open(client_key_path, 'rb') as f:
        client_private_pem = f.read()
    print("Client private key loaded.")

    while True:
        action = input("Register, Login, or Exit? (r/l/e): ").strip().lower()
        if action == 'e':
            print("Exiting...")
            break
        elif action not in ['r', 'l']:
            print("Invalid choice. Try again.")
            continue

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # 1. Send Hello (text)
            hello = HelloMessage(type="hello", client_cert=client_cert, nonce=random_nonce())
            s.sendall(json.dumps(hello.model_dump()).encode() + b'\n')

            # 2. Receive Server Hello (text)
            data = recv_text_line(s).decode()
            server_hello = parse_control_message(json.loads(data))
            if not verify_certificate_chain(server_hello.server_cert.encode(), is_server=True):
                print("Server cert invalid!")
                continue
            server_cert_pem = server_hello.server_cert.encode()
            print("Server cert stored.")

            # 3. DH (binary)
            print("Starting DH exchange on client")
            sys.stdout.flush()
            client_dh_priv, client_dh_pub = generate_dh_keypair()
            send_binary(s, client_dh_pub)
            print("Sent client DH pub")
            sys.stdout.flush()
            server_dh_pub = recv_binary(s)
            print("Received server DH pub")
            sys.stdout.flush()
            aes_key = derive_shared_secret(client_dh_priv, server_dh_pub)

            print("Control plane key established.")
            sys.stdout.flush()

            # 4. User Input for pre-message
            email = input("Email: ")

            pre_dict = {"type": "register" if action == 'r' else "login", "email": email}
            encrypted_pre = encrypt_aes(aes_key, json.dumps(pre_dict).encode())
            send_binary(s, encrypted_pre)

            # 5. Receive salt or fail (binary encrypted)
            print("Waiting for response")
            sys.stdout.flush()
            enc_resp = recv_binary(s)
            resp = decrypt_aes(aes_key, enc_resp)
            if resp.startswith(b"FAIL"):
                print("Error:", resp.decode())
                continue

            salt_b64 = resp.decode()
            print("Received salt")

            # 6. User Input for full message
            pwd = input("Password: ")
            username = input("Username: ") if action == 'r' else ""

            pwd_hash = hashlib.sha256(base64_decode(salt_b64) + pwd.encode()).digest()
            pwd_b64 = base64_encode(pwd_hash)

            if action == 'r':
                msg = RegisterMessage(type="register", email=email, username=username, pwd=pwd_b64, salt=salt_b64)
            else:
                msg = LoginMessage(type="login", email=email, pwd=pwd_b64, nonce=random_nonce())

            encrypted_msg = encrypt_aes(aes_key, json.dumps(msg.model_dump()).encode())
            send_binary(s, encrypted_msg)

            # 7. Response (binary encrypted)
            enc_final_resp = recv_binary(s)
            response = decrypt_aes(aes_key, enc_final_resp).decode()
            print("Server:", response)

if __name__ == "__main__":
    main()