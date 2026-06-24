from __future__ import annotations

import json
import socketserver
from pathlib import Path

from rivet.store import SecretStore
from rivet.tpm import SimulatedTpm


class AttestationHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline()
        if not raw:
            return
        try:
            request = json.loads(raw.decode())
        except json.JSONDecodeError:
            self._reply({"ok": False, "error": "invalid json"})
            return
        command = request.get("cmd")
        agent: RivetAgent = self.server.agent  # type: ignore[attr-defined]
        try:
            payload = agent.dispatch(command, request)
        except Exception as exc:
            self._reply({"ok": False, "error": str(exc)})
            return
        self._reply({"ok": True, **payload})

    def _reply(self, payload: dict) -> None:
        self.wfile.write((json.dumps(payload) + "\n").encode())


class AttestationServer(socketserver.ThreadingUnixStreamServer):
    def __init__(self, socket_path: Path, agent: RivetAgent) -> None:
        self.agent = agent
        if socket_path.exists():
            socket_path.unlink()
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(str(socket_path), AttestationHandler)


class RivetAgent:
    def __init__(self, tpm: SimulatedTpm, store: SecretStore) -> None:
        self.tpm = tpm
        self.store = store

    def dispatch(self, command: str, request: dict) -> dict:
        if command == "status":
            pcrs = {str(k): v.hex() for k, v in self.tpm.read_pcrs().items()}
            return {"pcrs": pcrs, "device": "/dev/tpmrm0" if _device() else "simulator"}
        if command == "quote":
            nonce = bytes.fromhex(request["nonce"])
            return {"quote": self.tpm.quote(nonce).hex()}
        if command == "unseal":
            blob = self.store.get(request["name"])
            secret = self.tpm.unseal(blob)
            return {"secret": secret.decode("utf-8", errors="replace")}
        raise ValueError(f"unknown command {command!r}")


def _device() -> bool:
    return Path("/dev/tpmrm0").exists()


def serve(socket_path: Path, agent: RivetAgent) -> AttestationServer:
    return AttestationServer(socket_path, agent)
