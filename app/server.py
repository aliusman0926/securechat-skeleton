"""Server workflow — plain TCP, no TLS."""

import socket
import json
import os
import secrets
from app.common.protocol import ServerHelloMessage, parse_control_message, PreMessage
from app.common.utils import random_nonce, base64_encode, send_binary, recv_binary, base64_decode
from app.crypto.pki import verify_certificate_chain
from app.crypto.dh import generate_dh_keypair, derive_shared_secret
from app.crypto.aes import encrypt_aes, decrypt_aes
from app.storage.db import register_user, verify_login, get_connection, DB_NAME
import sys

HOST = ''
PORT = 4444
CERTS_DIR = 'certs'

def load_cert(path: str) -> str:
    with open(path, 'r') as f:
        return f.read()

def recv_text_line(conn):
    data = b""
    while not data.endswith(b'\n'):
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Closed")
        data += chunk
    return data.strip()

def get_stored_salt(email: str) -> str | None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(f"USE `{DB_NAME}`")
            cur.execute("SELECT salt FROM users WHERE email = %s", (email,))
            result = cur.fetchone()
            return result[0] if result else None
    finally:
        conn.close()

def main():
    server_cert = load_cert(os.path.join(CERTS_DIR, 'server_cert.pem'))
    server_key_path = os.path.join(CERTS_DIR, 'server_key.pem')
    with open(server_key_path, 'rb') as f:
        server_private_pem = f.read()
    print("Server private key loaded.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server listening on {PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"Client connected: {addr}")

            # 1. Receive Hello (text)
            data = recv_text_line(conn).decode()
            hello = parse_control_message(json.loads(data))
            if hello.type != "hello":
                return

            if not verify_certificate_chain(hello.client_cert.encode(), is_server=False):
                print("Client cert invalid!")
                return
            client_cert_pem = hello.client_cert.encode()
            print("Client cert stored.")

            # 2. Send Server Hello (text)
            nonce = random_nonce()
            server_hello = ServerHelloMessage(type="server_hello", server_cert=server_cert, nonce=nonce)
            conn.sendall(json.dumps(server_hello.model_dump()).encode() + b'\n')

            # 3. Temporary DH (binary)
            print("Starting DH exchange on server")
            sys.stdout.flush()
            server_dh_priv, server_dh_pub = generate_dh_keypair()
            client_dh_pub = recv_binary(conn)
            print("Received client DH pub")
            sys.stdout.flush()
            send_binary(conn, server_dh_pub)
            print("Sent server DH pub")
            sys.stdout.flush()
            aes_key = derive_shared_secret(server_dh_priv, client_dh_pub)

            print("Control plane key established.")
            sys.stdout.flush()

            # 4. Receive pre-message (encrypted)
            enc_pre = recv_binary(conn)
            pre_json = decrypt_aes(aes_key, enc_pre).decode()
            pre_msg = PreMessage(**json.loads(pre_json))  # Use PreMessage for validation
            print(pre_msg)

            type_ = pre_msg.type
            email = pre_msg.email

            if type_ == "register":
                # Check if email exists
                if get_stored_salt(email):
                    response = b"FAIL_DUPLICATE"
                else:
                    salt = secrets.token_bytes(16)
                    salt_b64 = base64_encode(salt)
                    response = salt_b64.encode()
            elif type_ == "login":
                salt_b64 = get_stored_salt(email)
                if salt_b64:
                    response = salt_b64.encode()
                else:
                    response = b"FAIL_NOT_FOUND"
            else:
                response = b"FAIL_UNKNOWN"

            send_binary(conn, encrypt_aes(aes_key, response))

            if response.startswith(b"FAIL"):
                return

            # 5. Receive main message (encrypted)
            enc_main = recv_binary(conn)
            main_json = decrypt_aes(aes_key, enc_main).decode()
            msg = parse_control_message(json.loads(main_json))

            if msg.type == "register":
                success = register_user(msg.email, msg.username, msg.pwd, msg.salt)
                response = b"SUCCESS" if success else b"FAIL_DUPLICATE"
            elif msg.type == "login":
                username = verify_login(msg.email, msg.pwd, msg.nonce)
                response = b"SUCCESS" if username else b"FAIL_CREDENTIALS"
            else:
                response = b"FAIL_UNKNOWN"

            encrypted_response = encrypt_aes(aes_key, response)
            send_binary(conn, encrypted_response)
            print(f"Response: {response.decode()}")

if __name__ == "__main__":
    main()