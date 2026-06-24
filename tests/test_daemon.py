import json
import socket
import threading
from pathlib import Path

from rivet.daemon import RivetAgent, serve
from rivet.store import SecretStore
from rivet.tpm import open_backend


def test_status_and_quote_over_socket(tmp_path) -> None:
    tpm = open_backend(seed=b"daemon")
    store = SecretStore(tmp_path)
    blob = tpm.seal(b"from-daemon")
    store.put("api", blob)
    sock = tmp_path / "rivet.sock"
    server = serve(sock, RivetAgent(tpm, store))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status = _ask(sock, {"cmd": "status"})
        assert status["ok"] is True
        assert "0" in status["pcrs"]
        quote = _ask(sock, {"cmd": "quote", "nonce": "aa"})
        assert quote["ok"] is True
        unsealed = _ask(sock, {"cmd": "unseal", "name": "api"})
        assert unsealed["secret"] == "from-daemon"
        bad = _ask(sock, {"cmd": "nope"})
        assert bad["ok"] is False
        client = socket.socket(socket.AF_UNIX)
        client.connect(str(sock))
        client.sendall(b"{not-json\n")
        line = client.makefile().readline()
        client.close()
        assert json.loads(line)["ok"] is False
    finally:
        server.shutdown()
        server.server_close()


def _ask(path: Path, payload: dict) -> dict:
    client = socket.socket(socket.AF_UNIX)
    client.connect(str(path))
    client.sendall((json.dumps(payload) + "\n").encode())
    data = client.makefile().readline()
    client.close()
    return json.loads(data)
