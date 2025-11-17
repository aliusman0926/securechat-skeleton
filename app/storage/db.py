"""MySQL user store: salted SHA-256 passwords."""

import pymysql
from pymysql.err import OperationalError
import os
from dotenv import load_dotenv
from app.common.utils import sha256_hex, base64_decode, base64_encode
import secrets
import sys
import hashlib

# Load environment variables
load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '3306')),
    'user': os.getenv('DB_USER', 'scuser'),
    'password': os.getenv('DB_PASSWORD', 'scpass'),
    'charset': 'utf8mb4',
    'autocommit': True
}

# Database name
DB_NAME = os.getenv('DB_NAME', 'securechat')

def get_connection():
    """Return a new MySQL connection."""
    return pymysql.connect(**DB_CONFIG)

def init_db():
    """Create database and users table."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 1. Create database if not exists
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}`")
            # 2. Use the database
            cur.execute(f"USE `{DB_NAME}`")
            # 3. Create table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    username VARCHAR(32) UNIQUE NOT NULL,
                    pwd_hash VARCHAR(64) NOT NULL,
                    salt VARCHAR(24) NOT NULL
                )
            """)
        print(f"Database '{DB_NAME}' and table 'users' initialized successfully.")
    except Exception as e:
        print(f"DB init failed: {e}")
    finally:
        conn.close()

def register_user(email: str, username: str, hash_b64: str, salt_b64: str) -> bool:
    """Store the provided hash and salt."""
    hash_bytes = base64_decode(hash_b64)
    hash_hex = hash_bytes.hex()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(f"USE `{DB_NAME}`")
            cur.execute(
                "INSERT INTO users (email, username, pwd_hash, salt) VALUES (%s, %s, %s, %s)",
                (email, username, hash_hex, salt_b64)
            )
        return True
    except pymysql.err.IntegrityError:
        return False
    except Exception as e:
        print(f"Register failed: {e}")
        return False
    finally:
        conn.close()

def verify_login(email: str, pwd_b64: str, nonce: str) -> str | None:
    """Verify login. Returns username or None."""
    try:
        # Client sent: base64(sha256(salt || pwd))
        received_hash_bytes = base64_decode(pwd_b64)  # 32 bytes
        if len(received_hash_bytes) != 32:
            return None
        received_hash_hex = received_hash_bytes.hex()

        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(f"USE `{DB_NAME}`")
            cur.execute("SELECT username, pwd_hash FROM users WHERE email = %s", (email,))
            result = cur.fetchone()
            if result and result[1] == received_hash_hex:
                return result[0]
        return None
    except Exception as e:
        print(f"Login verify failed: {e}")
        return None
    finally:
        conn.close()

# CLI support for --init
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        init_db()