from rivet.crypto import aes_gcm_decrypt, aes_gcm_encrypt, hkdf_sha256


def test_hkdf_length() -> None:
    out = hkdf_sha256(b"ikm", b"info", 40)
    assert len(out) == 40


def test_encrypt_round_trip() -> None:
    key = hkdf_sha256(b"root", b"seal", 32)
    blob = aes_gcm_encrypt(key, b"hello", aad=b"pcr")
    assert aes_gcm_decrypt(key, blob, aad=b"pcr") == b"hello"
