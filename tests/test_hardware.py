import json
import subprocess
from pathlib import Path

import pytest

from rivet import MAGIC
from rivet.errors import PcrMismatch, SealError, TpmUnavailable
from rivet.hardware import HardwareTpm, parse_pcrread

PCR_TEXT = """
sha256:
  0 : 0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  1 : 0x10112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  2 : 0x20112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  3 : 0x30112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  4 : 0x40112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  5 : 0x50112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  6 : 0x60112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
  7 : 0x70112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
"""


def _ok(stdout: bytes = b"", stderr: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=stderr)


def test_parse_pcrread() -> None:
    parsed = parse_pcrread(PCR_TEXT)
    assert len(parsed) == 8
    assert parsed[0].hex().startswith("00112233")


def test_parse_pcrread_rejects_short_output() -> None:
    with pytest.raises(TpmUnavailable):
        parse_pcrread("  0 : 0x00\n")


def test_read_pcrs_uses_tpm2_pcrread() -> None:
    calls: list[list[str]] = []

    def runner(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return _ok(PCR_TEXT.encode())

    pcrs = HardwareTpm(runner).read_pcrs()
    assert calls[0][0] == "tpm2_pcrread"
    assert pcrs[7].hex().startswith("70112233")


def test_unseal_maps_policy_failure() -> None:
    blob = MAGIC + b"2" + json.dumps({"public": "aa", "private": "bb"}).encode()

    def runner(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if args[0] == "tpm2_unseal":
            return subprocess.CompletedProcess(args, 1, b"", b"policy check failed")
        return _ok()

    with pytest.raises(PcrMismatch):
        HardwareTpm(runner).unseal(blob)


def test_seal_quote_and_verify_with_fake_tools(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    def runner(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if args[0] == "tpm2_pcrread":
            return _ok(PCR_TEXT.encode())
        if args[0] == "tpm2_create":
            Path(args[args.index("-u") + 1]).write_bytes(b"pub")
            Path(args[args.index("-r") + 1]).write_bytes(b"priv")
        if args[0] == "tpm2_readpublic":
            Path(args[args.index("-o") + 1]).write_bytes(b"akpub")
        if args[0] == "tpm2_quote":
            Path(args[args.index("-m") + 1]).write_bytes(b"msg")
            Path(args[args.index("-s") + 1]).write_bytes(b"sig")
        if args[0] == "tpm2_unseal":
            return _ok(b"api-token")
        return _ok()

    tpm = HardwareTpm(runner)
    blob = tpm.seal(b"api-token")
    assert blob.startswith(MAGIC + b"2")
    assert tpm.unseal(blob) == b"api-token"
    quote = tpm.quote(b"nonce")
    assert tpm.verify_quote(quote, b"nonce")
    assert not tpm.verify_quote(quote, b"other")


def test_tool_failure_raises() -> None:
    def runner(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args, 1, b"", b"no such device")

    with pytest.raises(TpmUnavailable):
        HardwareTpm(runner).read_pcrs()


def test_corrupt_hardware_blob() -> None:
    with pytest.raises(SealError):
        HardwareTpm().unseal(MAGIC + b"2" + b"not-json")
