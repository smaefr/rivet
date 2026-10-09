import json
from pathlib import Path

from rivet.cli import main


def test_detect_and_pcr(capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("RIVET_SEED", "unit")
    monkeypatch.setattr("rivet.cli.tpm_device_present", lambda: False)
    monkeypatch.setattr("rivet.cli.tools_present", lambda: False)
    assert main(["--store", str(tmp_path), "--backend", "sim", "detect"]) == 0
    assert capsys.readouterr().out.strip() == "simulator"
    assert main(["--store", str(tmp_path), "pcr"]) == 0
    out = capsys.readouterr().out
    assert "pcr0:" in out
    assert "pcr7:" in out


def test_seal_unseal_via_cli(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("RIVET_SEED", "unit")
    monkeypatch.setattr("sys.stdin.buffer.read", lambda: b"token-42")
    assert main(["--store", str(tmp_path), "seal", "api"]) == 0
    capsys.readouterr()
    assert main(["--store", str(tmp_path), "unseal", "api"]) == 0
    assert capsys.readouterr().out == "token-42"


def test_baseline_and_status(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("RIVET_SEED", "unit")
    assert main(["--store", str(tmp_path), "baseline"]) == 0
    digest = capsys.readouterr().out.strip()
    assert len(digest) == 64
    assert main(["--store", str(tmp_path), "status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["digest"] == digest


def test_quote_verify(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("RIVET_SEED", "unit")
    assert main(["--store", str(tmp_path), "quote", "--nonce", "ab"]) == 0
    quote = capsys.readouterr().out.strip()
    assert main(["--store", str(tmp_path), "verify", quote, "--nonce", "ab"]) == 0
    capsys.readouterr()
    assert main(["--store", str(tmp_path), "verify", quote, "--nonce", "00"]) == 1
