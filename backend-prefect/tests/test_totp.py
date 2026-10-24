"""Vectores oficiales de RFC 4226 (HOTP) y RFC 6238 (TOTP, SHA1)."""
import base64

from app import totp

RFC_KEY = b"12345678901234567890"
RFC_SECRET_B32 = base64.b32encode(RFC_KEY).decode()


def test_hotp_rfc4226_vectors():
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [totp.hotp(RFC_KEY, c) for c in range(10)] == expected


def test_totp_rfc6238_vectors_sha1_8_digits():
    vectors = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
               1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}
    for t, code in vectors.items():
        assert totp.hotp(RFC_KEY, totp.time_step(t), digits=8) == code


def test_window_detection():
    now = 1_700_000_000
    for offset in (-1, 0, 1):
        code = totp.totp(RFC_SECRET_B32, now + offset * 30)
        assert totp.find_matching_window(RFC_SECRET_B32, code, at=now) == offset
    assert totp.find_matching_window(RFC_SECRET_B32, totp.totp(RFC_SECRET_B32, now + 90), at=now) is None


def test_base32_without_padding_and_lowercase():
    secret = totp.generate_secret()
    assert "=" not in secret
    assert totp.decode_base32(secret.lower()) == totp.decode_base32(secret)
