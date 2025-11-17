"""Protocol message models using Pydantic."""

from pydantic import BaseModel, Field, validator
from typing import Literal
import re

# Email regex (basic)
EMAIL_REGEX = r"^[^@]+@[^@]+\.[^@]+$"

class HelloMessage(BaseModel):
    type: Literal["hello"]
    client_cert: str = Field(..., description="PEM-encoded client certificate")
    nonce: str = Field(..., description="Base64-encoded 16-byte nonce")

class ServerHelloMessage(BaseModel):
    type: Literal["server_hello"]
    server_cert: str = Field(..., description="PEM-encoded server certificate")
    nonce: str = Field(..., description="Base64-encoded 16-byte nonce")

class RegisterMessage(BaseModel):
    type: Literal["register"]
    email: str = Field(..., pattern=EMAIL_REGEX)
    username: str = Field(..., min_length=3, max_length=32)
    pwd: str = Field(..., description="base64(sha256(salt || pwd))")
    salt: str = Field(..., description="base64-encoded salt")

    @validator('username')
    def username_alphanumeric(cls, v):
        if not re.fullmatch(r'[a-zA-Z0-9_]+', v):
            raise ValueError('username must be alphanumeric with underscores')
        return v

class LoginMessage(BaseModel):
    type: Literal["login"]
    email: str = Field(..., pattern=EMAIL_REGEX)
    pwd: str = Field(..., description="base64(sha256(salt || pwd))")
    nonce: str = Field(..., description="Base64-encoded nonce")

class PreMessage(BaseModel):
    type: Literal["register", "login"]
    email: str = Field(..., pattern=EMAIL_REGEX)

# --- add after LoginMessage ---
class ChatMessage(BaseModel):
    type: Literal["msg"]
    content: str                     # plain text from user
    seqno: int = Field(..., ge=1)
    ts: int = Field(..., ge=0)       # milliseconds since epoch
    sig: str                         # base64-encoded RSA signature

    @validator('content')
    def no_newline(cls, v):
        if '\n' in v:
            raise ValueError("content must not contain newline")
        return v

class ReceiptMessage(BaseModel):
    type: Literal["receipt"]
    transcript_hash: str  # hex SHA-256
    sig: str              # base64 RSA signature of the hash

# Union type for control plane messages
ControlMessage = HelloMessage | ServerHelloMessage | RegisterMessage | LoginMessage | ChatMessage

# Helper to parse JSON into correct model
def parse_control_message(data: dict) -> ControlMessage:
    msg_type = data.get("type")
    if msg_type == "hello":
        return HelloMessage(**data)
    elif msg_type == "server_hello":
        return ServerHelloMessage(**data)
    elif msg_type == "register":
        return RegisterMessage(**data)
    elif msg_type == "login":
        return LoginMessage(**data)
    else:
        raise ValueError(f"Unknown message type: {msg_type}")