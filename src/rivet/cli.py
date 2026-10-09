from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from rivet import PCR_BANK, __version__
from rivet.crypto import pcr_digest
from rivet.daemon import RivetAgent, serve
from rivet.store import SecretStore
from rivet.tpm import open_backend, tpm_device_present


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rivet", description="PCR-bound secret agent")
    parser.add_argument("--version", action="version", version=f"rivet {__version__}")
    parser.add_argument("--store", type=Path, help="state directory")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("pcr", help="print PCR 0-7")
    sub.add_parser("detect", help="report TPM device or simulator")
    sub.add_parser("baseline", help="snapshot current PCR 0-7")

    seal = sub.add_parser("seal", help="seal stdin to the current PCR baseline")
    seal.add_argument("name")

    unseal = sub.add_parser("unseal", help="unseal a named secret")
    unseal.add_argument("name")

    quote = sub.add_parser("quote", help="quote PCR 0-7 over a nonce")
    quote.add_argument("--nonce", required=True, help="hex nonce")

    verify = sub.add_parser("verify", help="verify a quote against live PCRs")
    verify.add_argument("quote")
    verify.add_argument("--nonce", required=True)

    daemon = sub.add_parser("daemon", help="serve a local attestation socket")
    daemon.add_argument("--socket", type=Path, default=Path("/tmp/rivet.sock"))

    sub.add_parser("status", help="print live PCR digest")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tpm = open_backend(seed=os.environ.get("RIVET_SEED", "").encode() or None)
    store = SecretStore(args.store)
    if args.cmd == "detect":
        if tpm_device_present():
            print("simulator (TPM device found, hardware backend not implemented)")
        else:
            print("simulator")
        return 0
    if args.cmd == "pcr":
        for idx, value in tpm.read_pcrs().items():
            print(f"pcr{idx}: {value.hex()}")
        return 0
    if args.cmd == "baseline":
        digest = pcr_digest(tpm.read_pcrs()).hex()
        store.write_meta({"pcrs": PCR_BANK, "digest": digest})
        print(digest)
        return 0
    if args.cmd == "seal":
        secret = sys.stdin.buffer.read()
        if not secret:
            print("rivet: empty stdin", file=sys.stderr)
            return 2
        blob = tpm.seal(secret)
        path = store.put(args.name, blob)
        print(path)
        return 0
    if args.cmd == "unseal":
        secret = tpm.unseal(store.get(args.name))
        sys.stdout.buffer.write(secret)
        return 0
    if args.cmd == "quote":
        quote = tpm.quote(bytes.fromhex(args.nonce))
        print(quote.hex())
        return 0
    if args.cmd == "verify":
        ok = tpm.verify_quote(bytes.fromhex(args.quote), bytes.fromhex(args.nonce))
        print("ok" if ok else "fail")
        return 0 if ok else 1
    if args.cmd == "status":
        print(json.dumps({"digest": pcr_digest(tpm.read_pcrs()).hex()}, indent=2))
        return 0
    if args.cmd == "daemon":
        agent = RivetAgent(tpm, store)
        server = serve(args.socket, agent)
        print(args.socket)
        server.serve_forever()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
