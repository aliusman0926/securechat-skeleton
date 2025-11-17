"""Server workflow — plain TCP, no TLS."""

import socket
import json
import os
import secrets
from app.common.protocol import ServerHelloMessage, parse_control_message, PreMessage
from app.common.utils import random_nonce, base64_encode, send_binary, recv_binary, base64_decode, now_ms
from app.crypto.pki import verify_certificate_chain
from app.crypto.dh import generate_dh_keypair, derive_shared_secret
from app.crypto.aes import encrypt_aes, decrypt_aes
from app.crypto.sign import rsa_verify
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

            # 6. Send final response (encrypted)
            encrypted_response = encrypt_aes(aes_key, response)
            send_binary(conn, encrypted_response)
            print(f"Response: {response.decode()}")

            if response != b"SUCCESS":
                return

            # === KEY AGREEMENT PHASE ===
            print("Starting session key agreement...")
            sys.stdout.flush()

            # Receive client's session DH public key
            enc_client_sess_pub = recv_binary(conn)
            client_sess_pub = decrypt_aes(aes_key, enc_client_sess_pub)
            print("Received client session DH public key")

            # Generate server DH keypair
            server_sess_priv, server_sess_pub = generate_dh_keypair()
            send_binary(conn, encrypt_aes(aes_key, server_sess_pub))
            print("Sent server session DH public key")

            session_key = derive_shared_secret(server_sess_priv, client_sess_pub)
            print("Session key K established.")
            sys.stdout.flush()

            # -------------------------------------------------
            #  CHAT LOOP (server, fixed signature)
            # -------------------------------------------------
            from app.common.chat import build_chat_message, sign_chat_message, compute_transcript_hash, build_receipt
            from app.common.input_thread import start_input_thread
            import queue
            import select

            seqno = 1
            transcript = []
            input_queue = queue.Queue()
            start_input_thread(input_queue)

            print("\n=== Secure Chat ===")
            while True:
                # --- Server input ---
                try:
                    line = input_queue.get_nowait()
                except queue.Empty:
                    line = None
                else:
                    msg = build_chat_message(line, seqno, server_private_pem)
                    msg["sig"] = sign_chat_message(msg, server_private_pem)
                    payload = json.dumps(msg, separators=(',', ':')).encode()
                    transcript.append(payload)
                    send_binary(conn, encrypt_aes(session_key, payload))
                    print(f"Server: {line}")
                    seqno += 1

                # --- Client message ---
                rlist, _, _ = select.select([conn], [], [], 0.1)
                if rlist:
                    try:
                        enc = recv_binary(conn)
                        payload_bytes = decrypt_aes(session_key, enc)
                        received = json.loads(payload_bytes.decode())
                        sig = received.pop("sig")

                        signed_json = json.dumps(received, separators=(',', ':')).encode()

                        if not rsa_verify(client_cert_pem, signed_json, sig):
                            print("[!] Client signature invalid")
                            continue
                        if received["seqno"] != seqno:
                            print(f"[!] Client seqno {received['seqno']} != {seqno}")
                            continue
                        if abs(received["ts"] - now_ms()) > 5000:
                            print("[!] Client message stale")
                            continue

                        transcript.append(payload_bytes)
                        print(f"Client: {received['content']}")
                        seqno += 1

                        if received["content"].lower() == "bye":
                            # --- Send bye ---
                            bye_msg = build_chat_message("bye", seqno, server_private_pem)
                            bye_msg["sig"] = sign_chat_message(bye_msg, server_private_pem)
                            bye_payload = json.dumps(bye_msg, separators=(',', ':')).encode()
                            transcript.append(bye_payload)
                            send_binary(conn, encrypt_aes(session_key, bye_payload))
                            print("Server: bye")
                            seqno += 1

                            # --- Receive client receipt ---
                            enc = recv_binary(conn)
                            client_receipt_bytes = decrypt_aes(session_key, enc)
                            client_receipt = json.loads(client_receipt_bytes.decode())
                            client_sig = client_receipt.pop("sig", None)
                            client_hash = client_receipt.get("transcript_hash")

                            # --- Compute hash ---
                            transcript_hash = compute_transcript_hash(transcript)

                            if (client_hash == transcript_hash and client_sig and
                                rsa_verify(client_cert_pem, client_hash.encode(), client_sig)):
                                print("Client receipt verified.")
                            else:
                                print("Client receipt INVALID!")

                            # --- Send server receipt ---
                            receipt = build_receipt(transcript_hash, server_private_pem)
                            receipt_payload = json.dumps(receipt, separators=(',', ':')).encode()
                            send_binary(conn, encrypt_aes(session_key, receipt_payload))
                            print(f"Sent receipt (hash: {transcript_hash[:16]}...)")

                            # --- Save ---
                            os.makedirs("logs", exist_ok=True)
                            with open("logs/transcript.txt", "w") as f:
                                for msg in transcript:
                                    try:
                                        f.write(json.loads(msg.decode())["content"] + "\n")
                                    except:
                                        pass
                                                    # --- Save full signed transcript ---
                            with open("logs/transcript_signed.json", "w") as f:
                                msgs = []
                                for b in transcript:
                                    try:
                                        msgs.append(json.loads(b.decode()))
                                    except:
                                        pass
                                json.dump(msgs, f, indent=2)
                            with open("logs/receipt_server.json", "w") as f:
                                json.dump(receipt, f, indent=2)
                            with open("logs/receipt_client.json", "w") as f:
                                json.dump(client_receipt, f, indent=2)
                            print("Saved transcript and receipts.")
                            break
                        
                    except Exception as e:
                        print(f"[!] Server receive error: {e}")
                        break
            # -------------------------------------------------
            # END OF CHAT LOOP (server, Windows-safe)
            # -------------------------------------------------

if __name__ == "__main__":
    main()