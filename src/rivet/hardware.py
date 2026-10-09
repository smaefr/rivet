from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from rivet import MAGIC, PCR_BANK
from rivet.errors import PcrMismatch, SealError, TpmUnavailable

SELECTION = "sha256:" + ",".join(str(i) for i in PCR_BANK)
Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def tools_present() -> bool:
    return shutil.which("tpm2_pcrread") is not None


def parse_pcrread(text: str) -> dict[int, bytes]:
    found: dict[int, bytes] = {}
    for line in text.splitlines():
        left, sep, right = line.partition(":")
        if not sep:
            continue
        index = left.strip()
        if not index.isdigit():
            continue
        hexpart = right.strip().removeprefix("0x").replace(" ", "")
        found[int(index)] = bytes.fromhex(hexpart)
    missing = [i for i in PCR_BANK if i not in found]
    if missing:
        raise TpmUnavailable(f"PCR read missing registers {missing}")
    return {i: found[i] for i in PCR_BANK}


def _default_runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, check=False, **kwargs)  # type: ignore[arg-type]


class HardwareTpm:
    """Seal and quote with tpm2-tools against /dev/tpmrm0."""

    def __init__(self, runner: Runner | None = None) -> None:
        self._run = runner or _default_runner

    def read_pcrs(self, indices: tuple[int, ...] = PCR_BANK) -> dict[int, bytes]:
        result = self._run(["tpm2_pcrread", "sha256:" + ",".join(str(i) for i in indices)])
        if result.returncode != 0:
            raise TpmUnavailable(result.stderr.decode("utf-8", "replace").strip() or "tpm2_pcrread failed")
        parsed = parse_pcrread(result.stdout.decode("utf-8", "replace"))
        return {i: parsed[i] for i in indices}

    def seal(self, secret: bytes, indices: tuple[int, ...] = PCR_BANK) -> bytes:
        if indices != PCR_BANK:
            raise SealError("hardware seal is bound to PCR 0-7")
        with tempfile.TemporaryDirectory(prefix="rivet-") as raw:
            work = Path(raw)
            policy = work / "policy.dat"
            primary = work / "primary.ctx"
            secret_path = work / "secret.bin"
            pub = work / "seal.pub"
            priv = work / "seal.priv"
            secret_path.write_bytes(secret)
            self._must(
                [
                    "tpm2_createpolicy",
                    "--policy-pcr",
                    "-l",
                    SELECTION,
                    "-L",
                    str(policy),
                ]
            )
            self._must(["tpm2_createprimary", "-C", "o", "-c", str(primary)])
            self._must(
                [
                    "tpm2_create",
                    "-C",
                    str(primary),
                    "-i",
                    str(secret_path),
                    "-u",
                    str(pub),
                    "-r",
                    str(priv),
                    "-L",
                    str(policy),
                ]
            )
            payload = {
                "public": pub.read_bytes().hex(),
                "private": priv.read_bytes().hex(),
            }
        body = json.dumps(payload).encode()
        return MAGIC + b"2" + body

    def unseal(self, blob: bytes, indices: tuple[int, ...] = PCR_BANK) -> bytes:
        if indices != PCR_BANK or not blob.startswith(MAGIC + b"2"):
            raise SealError("not a hardware sealed blob")
        try:
            payload = json.loads(blob[len(MAGIC) + 1 :])
            pub_bytes = bytes.fromhex(payload["public"])
            priv_bytes = bytes.fromhex(payload["private"])
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            raise SealError("hardware blob is corrupt") from exc
        with tempfile.TemporaryDirectory(prefix="rivet-") as raw:
            work = Path(raw)
            primary = work / "primary.ctx"
            pub = work / "seal.pub"
            priv = work / "seal.priv"
            loaded = work / "seal.ctx"
            pub.write_bytes(pub_bytes)
            priv.write_bytes(priv_bytes)
            self._must(["tpm2_createprimary", "-C", "o", "-c", str(primary)])
            self._must(
                ["tpm2_load", "-C", str(primary), "-u", str(pub), "-r", str(priv), "-c", str(loaded)]
            )
            result = self._run(
                ["tpm2_unseal", "-c", str(loaded), "-p", f"pcr:{SELECTION}"]
            )
        if result.returncode != 0:
            err = result.stderr.decode("utf-8", "replace").lower()
            if "policy" in err or "pcr" in err:
                raise PcrMismatch("TPM refused to unseal; PCR 0-7 drifted")
            raise SealError(err.strip() or "tpm2_unseal failed")
        return result.stdout

    def quote(self, nonce: bytes, indices: tuple[int, ...] = PCR_BANK) -> bytes:
        from rivet.crypto import pcr_digest

        with tempfile.TemporaryDirectory(prefix="rivet-") as raw:
            work = Path(raw)
            ak = work / "ak.ctx"
            message = work / "quote.msg"
            signature = work / "quote.sig"
            public = work / "ak.pub"
            nonce_path = work / "nonce.bin"
            nonce_path.write_bytes(nonce)
            self._must(["tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", str(ak)])
            self._must(["tpm2_readpublic", "-c", str(ak), "-o", str(public)])
            self._must(
                [
                    "tpm2_quote",
                    "-c",
                    str(ak),
                    "-l",
                    SELECTION,
                    "-q",
                    str(nonce_path),
                    "-m",
                    str(message),
                    "-s",
                    str(signature),
                ]
            )
            body = {
                "nonce": nonce.hex(),
                "pcr_digest": pcr_digest(self.read_pcrs(indices)).hex(),
                "message": message.read_bytes().hex(),
                "signature": signature.read_bytes().hex(),
                "public": public.read_bytes().hex(),
            }
        return MAGIC + b"Q" + json.dumps(body).encode()

    def verify_quote(self, quote: bytes, nonce: bytes, indices: tuple[int, ...] = PCR_BANK) -> bool:
        from rivet.crypto import pcr_digest

        if not quote.startswith(MAGIC + b"Q"):
            return False
        try:
            body = json.loads(quote[len(MAGIC) + 1 :])
        except json.JSONDecodeError:
            return False
        if bytes.fromhex(body.get("nonce", "")) != nonce:
            return False
        if not body.get("message") or not body.get("signature"):
            return False
        live = pcr_digest(self.read_pcrs(indices)).hex()
        return body.get("pcr_digest") == live

    def _must(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        result = self._run(args)
        if result.returncode != 0:
            err = result.stderr.decode("utf-8", "replace").strip()
            raise TpmUnavailable(err or f"{args[0]} failed")
        return result
