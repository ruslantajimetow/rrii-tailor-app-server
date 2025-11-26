import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from jose import jwt
import bcrypt
import hashlib

load_dotenv()

# 🔹 JWT config from env
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)


def _normalize_password(password: str) -> bytes:
    """
    Step 1: Normalize password using SHA-256.

    - Take the plain password string.
    - Encode it as UTF-8 bytes.
    - Compute SHA-256 digest.
    - Convert digest to hex string (64 hex chars).
    - Encode that hex string back to bytes.

    Result:
    - Always a fixed-length <= 64 bytes string.
    - Safe to pass into bcrypt (no 72-byte error).
    """
    # convert "my_password" -> b"my_password"
    password_bytes = password.encode("utf-8")

    # sha256(...) -> 32-byte digest; hexdigest() -> 64-char hex string
    sha_hex = hashlib.sha256(password_bytes).hexdigest()

    # encode hex string into bytes for bcrypt
    return sha_hex.encode("utf-8")


def hash_password(password: str) -> str:
    """
    Hash a plain password using SHA-256 + bcrypt.

    1) Normalize password with SHA-256 (fix length).
    2) Generate a random salt with bcrypt.gensalt().
    3) Hash the normalized password with that salt.
    4) Return the final bcrypt hash as a UTF-8 string for storage in DB.
    """
    # 1) Normalize: avoid 72-byte bcrypt limit
    normalized = _normalize_password(password)  # bytes

    # 2) Salt generation (cost factor inside gensalt)
    salt = bcrypt.gensalt()

    # 3) bcrypt.hashpw(secret_bytes, salt) -> hash bytes
    hashed = bcrypt.hashpw(normalized, salt)

    # 4) Decode bytes -> str so we can store in PostgreSQL as TEXT
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a stored bcrypt hash.

    1) Normalize the plain password with the same SHA-256 step.
    2) Encode the stored hash string back into bytes.
    3) Use bcrypt.checkpw() to compare.
    4) Returns True if matches, False otherwise.
    """
    # 1) Normalize input password (same as in hash_password)
    normalized = _normalize_password(plain_password)  # bytes

    # 2) Stored hash is str -> encode to bytes
    hashed_bytes = hashed_password.encode("utf-8")

    # 3) bcrypt.checkpw(...) -> True / False
    return bcrypt.checkpw(normalized, hashed_bytes)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with `data` as payload and an expiration.

    Steps:
    1) Copy input dict to avoid mutating caller's object.
    2) Compute expiry time (now + delta or default minutes).
    3) Add "exp" field to payload.
    4) Encode using jose.jwt with HS256 and your secret key.
    5) Return token string (e.g., 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...').
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt
