"""Implementación de TOTP (RFC 6238) / HOTP (RFC 4226) desde cero.

Solo se usan primitivas estándar: hmac + hashlib (HMAC-SHA1) y base64 (Base32).
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from .config import ISSUER, TOTP_DIGITS, TOTP_PERIOD


def generate_secret(num_bytes: int = 20) -> str:
    """Semilla aleatoria de 160 bits codificada en Base32 sin padding."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode().rstrip("=")


def decode_base32(secret: str) -> bytes:
    clean = secret.replace(" ", "").upper()
    clean += "=" * (-len(clean) % 8)
    return base64.b32decode(clean)


def hotp(key: bytes, counter: int, digits: int = TOTP_DIGITS) -> str:
    # 1. HMAC-SHA1(K, C) con el contador como entero big-endian de 8 bytes
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    # 2. Truncamiento dinámico: los 4 bits bajos del último byte dan el offset
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    # 3. Reducción módulo 10^d
    return str(binary % (10 ** digits)).zfill(digits)


def time_step(at: float | None = None, period: int = TOTP_PERIOD) -> int:
    return int((time.time() if at is None else at) // period)


def totp(secret_b32: str, at: float | None = None) -> str:
    return hotp(decode_base32(secret_b32), time_step(at))


def find_matching_window(secret_b32: str, code: str, at: float | None = None,
                         drift: int = 1) -> int | None:
    """Devuelve el desfase (-1, 0, +1) de la ventana que coincide, o None."""
    key = decode_base32(secret_b32)
    current = time_step(at)
    for offset in range(-drift, drift + 1):
        if hmac.compare_digest(hotp(key, current + offset), code):
            return offset
    return None


def provisioning_uri(secret_b32: str, account: str) -> str:
    label = quote(f"{ISSUER}:{account}")
    params = urlencode({
        "secret": secret_b32,
        "issuer": ISSUER,
        "algorithm": "SHA1",
        "digits": TOTP_DIGITS,
        "period": TOTP_PERIOD,
    })
    return f"otpauth://totp/{label}?{params}"
