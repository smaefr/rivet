import pytest

from rivet.errors import SealError
from rivet.store import SecretStore


def test_put_and_get(tmp_path) -> None:
    store = SecretStore(tmp_path)
    store.put("db", b"sealed-bytes")
    assert store.get("db") == b"sealed-bytes"


def test_missing_secret(tmp_path) -> None:
    store = SecretStore(tmp_path)
    with pytest.raises(SealError):
        store.get("missing")


def test_rejects_odd_names(tmp_path) -> None:
    store = SecretStore(tmp_path)
    with pytest.raises(SealError):
        store.path_for("../etc")
