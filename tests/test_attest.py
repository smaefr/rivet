from rivet.tpm import SimulatedTpm


def test_quote_verifies_against_live_pcrs() -> None:
    tpm = SimulatedTpm()
    nonce = bytes.fromhex("aabbccdd")
    quote = tpm.quote(nonce)
    assert tpm.verify_quote(quote, nonce)


def test_quote_fails_after_boot_change() -> None:
    tpm = SimulatedTpm()
    nonce = b"nonce-1"
    quote = tpm.quote(nonce)
    tpm.extend(0, b"bios-update")
    assert not tpm.verify_quote(quote, nonce)


def test_wrong_nonce_is_rejected() -> None:
    tpm = SimulatedTpm()
    quote = tpm.quote(b"one")
    assert not tpm.verify_quote(quote, b"two")
