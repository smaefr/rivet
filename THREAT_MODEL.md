# Threat model

Rivet is a mini PCR-bound secret agent, not a full measured-boot stack.

## Assets

- Sealed wrapping keys and the secrets they encrypt
- Attestation quotes used by a remote verifier
- The PCR 0–7 baseline

## Attack surface

- Local CLI and Unix socket
- Sealed blobs on disk
- Optional `/dev/tpmrm0`
- Simulator storage root in process memory

## STRIDE

| Category | Risk | Handling |
| --- | --- | --- |
| Spoofing | Fake quotes | Quotes are MAC'd with an attestation key held by the TPM/simulator |
| Tampering | Edit a sealed blob's PCR digest | Blob MAC covers digest + ciphertext |
| Repudiation | No durable audit log | Explicit tradeoff; this is a mini tool |
| Information disclosure | Socket returns unsealed secrets | Unix socket, local-only; do not expose it |
| Denial of service | PCR extend locks secrets | Intended: reboot to a known image to recover |
| Elevation | Skip PCR check | Unseal recomputes the live digest and fails closed |

## Tradeoffs

- Simulator mode is for development. It is not hardware root of trust.
- Hardware mode shells out to `tpm2-tools` and trusts that binary plus `/dev/tpmrm0`.
- No full EK certificate chain or TPM 2.0 policy sessions.
- PCR 0–7 only. Application PCRs (8+) are out of scope.
- No remote verifier service; `rivet verify` is a local check.
