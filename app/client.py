"""Client workflow — plain TCP, no TLS."""

import socket
import json
import os
import hashlib
import secrets
from app.common.protocol import HelloMessage, RegisterMessage, LoginMessage, parse_control_message
from app.common.utils import random_nonce, base64_encode, base64_decode, send_binary, recv_binary, now_ms
from app.crypto.pki import verify_certificate_chain
from app.crypto.dh import generate_dh_keypair, derive_shared_secret
from app.crypto.aes import encrypt_aes, decrypt_aes
from app.crypto.sign import rsa_verify
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
            return
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
            sys.stdout.flush()
            enc_resp = recv_binary(s)
            resp = decrypt_aes(aes_key, enc_resp)
            if resp.startswith(b"FAIL"):
                print("Error:", resp.decode())
                continue

            salt_b64 = resp.decode()

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

            if response != "SUCCESS":
                continue  # retry login/register

            # === KEY AGREEMENT PHASE ===
            print("Starting session key agreement...")
            sys.stdout.flush()

            # Generate new DH keypair for session
            client_sess_priv, client_sess_pub = generate_dh_keypair()
            send_binary(s, encrypt_aes(aes_key, client_sess_pub))
            print("Sent session DH public key (encrypted)")

            enc_server_sess_pub = recv_binary(s)
            server_sess_pub = decrypt_aes(aes_key, enc_server_sess_pub)
            print("Received server session DH public key")

            session_key = derive_shared_secret(client_sess_priv, server_sess_pub)
            print("Session key K established.")
            sys.stdout.flush()

            # -------------------------------------------------
            #  CHAT LOOP (Fixed Signature Verification)
            # -------------------------------------------------
            from app.common.chat import build_chat_message, sign_chat_message, compute_transcript_hash, build_receipt
            from app.common.input_thread import start_input_thread
            import queue
            import select

            seqno = 1
            transcript = []
            input_queue = queue.Queue()
            input_thread = start_input_thread(input_queue)

            print("\n=== Secure Chat (type 'bye' to quit) ===")
            while True:
                # --- User input ---
                try:
                    line = input_queue.get_nowait()
                except queue.Empty:
                    line = None
                else:
                    if line.lower() == "bye":
                        # --- Send bye ---
                        msg = build_chat_message("bye", seqno, client_private_pem)
                        msg["sig"] = sign_chat_message(msg, client_private_pem)
                        payload = json.dumps(msg, separators=(',', ':')).encode()
                        transcript.append(payload)
                        send_binary(s, encrypt_aes(session_key, payload))
                        print("You: bye")
                        seqno += 1

                        # --- Wait for server bye ---
                        while True:
                            rlist, _, _ = select.select([s], [], [], 1.0)
                            if not rlist:
                                continue
                            enc = recv_binary(s)
                            payload_bytes = decrypt_aes(session_key, enc)
                            received = json.loads(payload_bytes.decode())
                            sig = received.pop("sig")
                            signed_json = json.dumps(received, separators=(',', ':')).encode()

                            if not rsa_verify(server_cert_pem, signed_json, sig):
                                print("[!] Invalid server bye")
                                break
                            if received["seqno"] != seqno:
                                print("[!] Seqno mismatch on server bye")
                                break
                            if abs(received["ts"] - now_ms()) > 5000:
                                print("[!] Stale server bye")
                                break

                            transcript.append(payload_bytes)
                            print("Server: bye")
                            seqno += 1
                            break

                        # --- Compute hash ---
                        transcript_hash = compute_transcript_hash(transcript)

                        # --- Send receipt ---
                        receipt = build_receipt(transcript_hash, client_private_pem)
                        receipt_payload = json.dumps(receipt, separators=(',', ':')).encode()
                        send_binary(s, encrypt_aes(session_key, receipt_payload))
                        print(f"Sent receipt (hash: {transcript_hash[:16]}...)")

                        # --- Receive server receipt ---
                        enc = recv_binary(s)
                        server_receipt_bytes = decrypt_aes(session_key, enc)
                        server_receipt = json.loads(server_receipt_bytes.decode())
                        server_sig = server_receipt.pop("sig", None)
                        server_hash = server_receipt.get("transcript_hash")

                        if (server_hash == transcript_hash and server_sig and
                            rsa_verify(server_cert_pem, server_hash.encode(), server_sig)):
                            print("Server receipt verified.")
                        else:
                            print("Server receipt INVALID!")

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
                        with open("logs/receipt_client.json", "w") as f:
                            json.dump(receipt, f, indent=2)
                        print("Saved transcript and receipts in logs/")
                        break

                    msg = build_chat_message(line, seqno, client_private_pem)
                    msg["sig"] = sign_chat_message(msg, client_private_pem)
                    payload = json.dumps(msg, separators=(',', ':')).encode()
                    transcript.append(payload)
                    send_binary(s, encrypt_aes(session_key, payload))
                    print(f"You: {line}")
                    seqno += 1

                # --- Receive message ---
                rlist, _, _ = select.select([s], [], [], 0.1)
                if rlist:
                    try:
                        enc = recv_binary(s)
                        payload_bytes = decrypt_aes(session_key, enc)  # <-- raw bytes
                        received = json.loads(payload_bytes.decode())
                        sig = received.pop("sig")

                        # --- CRITICAL: Reconstruct exact signed JSON ---
                        signed_json = json.dumps(received, separators=(',', ':')).encode()

                        if not rsa_verify(server_cert_pem, signed_json, sig):
                            print("[!] Signature verification failed")
                            continue

                        expected_seq = seqno
                        if received["seqno"] != expected_seq:
                            print(f"[!] Seqno mismatch: {received['seqno']} != {expected_seq}")
                            continue
                        if abs(received["ts"] - now_ms()) > 5000:
                            print("[!] Message too old/future")
                            continue

                        transcript.append(payload_bytes)
                        print(f"Server: {received['content']}")
                        seqno += 1

                        if received["content"].lower() == "bye":
                            print("Server ended the session.")
                            break
                    except Exception as e:
                        print(f"[!] Receive error: {e}")
                        break
            # -------------------------------------------------
            #  END OF CHAT LOOP (Windows-safe)
            # -------------------------------------------------

if __name__ == "__main__":
    main()