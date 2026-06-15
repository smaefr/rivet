import pytest

from rivet.errors import PcrMismatch, SealError
from rivet.tpm import SimulatedTpm


def test_unseal_round_trip() -> None:
    tpm = SimulatedTpm()
    blob = tpm.seal(b"api-token-value")
    assert tpm.unseal(blob) == b"api-token-value"


def test_unseal_fails_after_pcr_extend() -> None:
    tpm = SimulatedTpm()
    blob = tpm.seal(b"private-key")
    tpm.extend(4, b"new-kernel")
    with pytest.raises(PcrMismatch):
        tpm.unseal(blob)


def test_wrong_pcr_selection_is_rejected() -> None:
    tpm = SimulatedTpm()
    blob = bytearray(tpm.seal(b"x"))
    blob[8] = 3
    with pytest.raises(SealError):
        tpm.unseal(bytes(blob))


def test_tampered_blob_is_rejected() -> None:
    tpm = SimulatedTpm()
    blob = bytearray(tpm.seal(b"secret"))
    blob[-1] ^= 0x01
    with pytest.raises(SealError):
        tpm.unseal(bytes(blob))
