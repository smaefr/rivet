# Rivet

A small host attestation agent. Rivet reads TPM 2.0 PCRs 0–7 (BIOS, bootloader,
kernel), seals a wrapping key to that baseline, and refuses to unseal if the
boot state drifted. Secrets such as API tokens stay ciphertext until the TPM
policy matches.

When `tpm2-tools` can read `/dev/tpmrm0`, `rivet --backend auto` seals and
quotes on the hardware TPM. Otherwise it uses an in-process simulator with the
same PCR-binding rule so the tool still runs on a laptop.

```bash
pip install -e ".[dev]"
echo 'api-token' | rivet seal api
rivet unseal api
make test
```

## Data flow

```mermaid
flowchart LR
  boot[Firmware bootloader kernel] --> pcrs[PCR 0-7]
  pcrs --> tpm[TPM 2.0 or simulator]
  tpm --> seal[Seal AES wrapping key]
  secret[API token] --> wrap[Encrypt]
  seal --> wrap
  wrap --> disk[Sealed blob]
  disk --> unseal[Unseal]
  tpm --> unseal
  unseal -->|PCR match| plain[Plaintext]
  unseal -->|PCR drift| deny[Refuse]
  nonce[Challenger nonce] --> quote[Quote]
  tpm --> quote
```

Trust boundary is the TPM (or the simulator process in tests). The daemon only
listens on a Unix socket.

## Commands

- `rivet detect` — `hardware` or `simulator`
- `rivet pcr` — dump PCR 0–7
- `rivet baseline` — store the current digest
- `rivet seal NAME` — encrypt stdin to the live PCR policy
- `rivet unseal NAME` — decrypt only if PCRs still match
- `rivet quote --nonce HEX` / `rivet verify QUOTE --nonce HEX`
- `rivet daemon --socket /tmp/rivet.sock`

## License

MIT. See [LICENSE](LICENSE).
