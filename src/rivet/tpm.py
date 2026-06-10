from __future__ import annotations

import os
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from rivet import PCR_BANK
from rivet.crypto import aes_gcm_decrypt, aes_gcm_encrypt, hmac_ok, hkdf_sha256, pcr_digest
from rivet.errors import PcrMismatch, SealError, TpmUnavailable

TPM_DEVICE = Path("/dev/tpmrm0")
EMPTY_PCR = bytes(32)


@dataclass
class SimulatedTpm:
    """In-process TPM stand-in that preserves PCR-bound unseal semantics."""

    pcrs: dict[int, bytes] = field(default_factory=lambda: {i: EMPTY_PCR for i in PCR_BANK})
    storage_root: bytes = field(default_factory=lambda: os.urandom(32))
    ak: bytes = field(default_factory=lambda: os.urandom(32))
    ek_name: bytes = field(default_factory=lambda: sha256(b"rivet-sim-ek").digest())

    def read_pcrs(self, indices: tuple[int, ...] = PCR_BANK) -> dict[int, bytes]:
        return {i: self.pcrs[i] for i in indices}

    def extend(self, index: int, data: bytes) -> None:
        current = self.pcrs[index]
        self.pcrs[index] = sha256(current + sha256(data).digest()).digest()

    def reset_pcrs(self, values: dict[int, bytes] | None = None) -> None:
        if values is None:
            self.pcrs = {i: EMPTY_PCR for i in PCR_BANK}
        else:
            self.pcrs.update(values)

    def seal(self, secret: bytes, indices: tuple[int, ...] = PCR_BANK) -> bytes:
        pcrs = self.read_pcrs(indices)
        digest = pcr_digest(pcrs)
        wrap = hkdf_sha256(self.storage_root, b"seal" + digest)
        body = aes_gcm_encrypt(wrap, secret, aad=digest)
        mac = hkdf_sha256(self.storage_root, b"mac" + digest + body)
        header = bytes(indices) + bytes([len(indices)])
        return header + digest + body + mac

    def unseal(self, blob: bytes, indices: tuple[int, ...] = PCR_BANK) -> bytes:
        count = blob[len(indices)]
        if count != len(indices):
            raise SealError("pcr selection mismatch")
        digest = blob[len(indices) + 1 : len(indices) + 1 + 32]
        rest = blob[len(indices) + 1 + 32 :]
        body, mac = rest[:-32], rest[-32:]
        live = pcr_digest(self.read_pcrs(indices))
        if live != digest:
            raise PcrMismatch("PCR 0-7 drifted from the sealed baseline")
        expected = hkdf_sha256(self.storage_root, b"mac" + digest + body)
        if not hmac_ok(mac, expected):
            raise SealError("sealed blob MAC mismatch")
        wrap = hkdf_sha256(self.storage_root, b"seal" + digest)
        try:
            return aes_gcm_decrypt(wrap, body, aad=digest)
        except ValueError as exc:
            raise SealError("unseal decrypt failed") from exc

    def quote(self, nonce: bytes, indices: tuple[int, ...] = PCR_BANK) -> bytes:
        digest = pcr_digest(self.read_pcrs(indices))
        payload = nonce + digest + self.ek_name
        sig = hkdf_sha256(self.ak, b"quote" + payload)
        return payload + sig

    def verify_quote(self, quote: bytes, nonce: bytes, indices: tuple[int, ...] = PCR_BANK) -> bool:
        need = len(nonce) + 32 + 32 + 32
        if len(quote) != need:
            return False
        got_nonce = quote[: len(nonce)]
        if got_nonce != nonce:
            return False
        payload, sig = quote[:-32], quote[-32:]
        expected = hkdf_sha256(self.ak, b"quote" + payload)
        if not hmac_ok(sig, expected):
            return False
        digest = pcr_digest(self.read_pcrs(indices))
        return payload[len(nonce) : len(nonce) + 32] == digest


def tpm_device_present() -> bool:
    return TPM_DEVICE.exists()


def open_backend(seed: bytes | None = None) -> SimulatedTpm:
    """Always usable simulator. Hardware path is detected separately."""
    tpm = SimulatedTpm()
    if seed is not None:
        tpm.storage_root = sha256(b"root" + seed).digest()
        tpm.ak = sha256(b"ak" + seed).digest()
        for i in PCR_BANK:
            tpm.pcrs[i] = sha256(seed + bytes([i])).digest()
    return tpm


def require_or_simulate(prefer_hw: bool = False) -> SimulatedTpm:
    if prefer_hw and not tpm_device_present():
        raise TpmUnavailable(f"{TPM_DEVICE} is missing")
    return open_backend()
