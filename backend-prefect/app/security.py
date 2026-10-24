import hashlib
import hmac
import secrets
import time
import uuid

import jwt

from .config import (ACCESS_TTL_SECONDS, BACKUP_CODES_COUNT, JWT_ALGORITHM,
                     JWT_SECRET, PRE_AUTH_TTL_SECONDS)

SCOPE_PRE_AUTH = "pre_auth"
SCOPE_ACCESS = "access"


class InvalidToken(Exception):
    pass


# --- Contraseñas (PBKDF2, librería estándar) ---

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt, expected = stored.split("$", 1)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return hmac.compare_digest(digest.hex(), expected)


# --- Códigos de respaldo (se guardan hasheados) ---

def generate_backup_codes() -> list[str]:
    return [f"{secrets.randbelow(10**8):08d}" for _ in range(BACKUP_CODES_COUNT)]


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


# --- JWT: Pre-Auth Token vs Access Token ---

def _encode(payload: dict, ttl: int) -> str:
    now = int(time.time())
    payload = {**payload, "iat": now, "exp": now + ttl, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def issue_pre_auth_token(user_id: str, username: str) -> str:
    """Token restringido: solo sirve para los endpoints de 2FA."""
    return _encode({"sub": user_id, "username": username,
                    "scope": SCOPE_PRE_AUTH, "mfa_verified": False}, PRE_AUTH_TTL_SECONDS)


def issue_access_token(user_id: str, username: str, method: str) -> str:
    return _encode({"sub": user_id, "username": username, "scope": SCOPE_ACCESS,
                    "mfa_verified": True, "amr": ["pwd", method]}, ACCESS_TTL_SECONDS)


def decode_token(token: str, expected_scope: str) -> dict:
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise InvalidToken(f"Token inválido: {exc}") from exc
    if claims.get("scope") != expected_scope:
        raise InvalidToken(f"Se esperaba un token con scope '{expected_scope}'")
    return claims
