from pathlib import Path

import pytest

from rivet.cli import main
from rivet.errors import TpmUnavailable
from rivet.tpm import require_or_simulate, tpm_device_present


def test_require_hw_without_device(monkeypatch) -> None:
    monkeypatch.setattr("rivet.tpm.tpm_device_present", lambda: False)
    with pytest.raises(TpmUnavailable):
        require_or_simulate(prefer_hw=True)


def test_device_helper_matches_path() -> None:
    assert tpm_device_present() is Path("/dev/tpmrm0").exists()


def test_seal_rejects_empty_stdin(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr("sys.stdin.buffer.read", lambda: b"")
    assert main(["--store", str(tmp_path), "seal", "x"]) == 2
    assert "empty stdin" in capsys.readouterr().err
