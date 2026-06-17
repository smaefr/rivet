from __future__ import annotations

import json
from pathlib import Path

from rivet.errors import SealError

DEFAULT_DIR = Path.home() / ".rivet"


class SecretStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root is not None else DEFAULT_DIR
        self.root.mkdir(parents=True, exist_ok=True)
        self._meta = self.root / "state.json"

    def path_for(self, name: str) -> Path:
        if not name.replace("-", "").replace("_", "").isalnum():
            raise SealError(f"invalid secret name {name!r}")
        return self.root / f"{name}.sealed"

    def put(self, name: str, blob: bytes) -> Path:
        path = self.path_for(name)
        path.write_bytes(blob)
        return path

    def get(self, name: str) -> bytes:
        path = self.path_for(name)
        if not path.exists():
            raise SealError(f"no sealed secret named {name!r}")
        return path.read_bytes()

    def write_meta(self, data: dict) -> None:
        self._meta.write_text(json.dumps(data, indent=2) + "\n")

    def read_meta(self) -> dict:
        if not self._meta.exists():
            return {}
        return json.loads(self._meta.read_text())
