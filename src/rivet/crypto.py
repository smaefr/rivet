from __future__ import annotations

import os
from hashlib import sha256

from rivet import MAGIC


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    salt = sha256(b"rivet-hkdf").digest()
    prk = _hmac(salt, ikm)
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = _hmac(prk, block + info + bytes([counter]))
        okm += block
        counter += 1
    return okm[:length]


def _hmac(key: bytes, data: bytes) -> bytes:
    import hmac

    return hmac.new(key, data, sha256).digest()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
    except ImportError:
        # Mini fallback: HMAC-authenticated stream. Tests never require cryptography.
        stream = hkdf_sha256(key, nonce + aad, len(plaintext))
        ct = xor_bytes(plaintext, stream)
        tag = _hmac(key, nonce + aad + ct)
        return nonce + ct + tag


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    nonce, rest = blob[:12], blob[12:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(key).decrypt(nonce, rest, aad)
    except ImportError:
        ct, tag = rest[:-32], rest[-32:]
        expected = _hmac(key, nonce + aad + ct)
        if not hmac_ok(tag, expected):
            raise ValueError("auth tag mismatch")
        stream = hkdf_sha256(key, nonce + aad, len(ct))
        return xor_bytes(ct, stream)


def hmac_ok(left: bytes, right: bytes) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def pcr_digest(values: dict[int, bytes]) -> bytes:
    material = MAGIC + b"".join(values[i] for i in sorted(values))
    return sha256(material).digest()
