from rivet.crypto import pcr_digest
from rivet.tpm import SimulatedTpm


def test_default_pcrs_are_32_bytes() -> None:
    tpm = SimulatedTpm()
    pcrs = tpm.read_pcrs()
    assert list(pcrs) == list(range(8))
    assert all(len(value) == 32 for value in pcrs.values())


def test_extend_changes_only_one_register() -> None:
    tpm = SimulatedTpm()
    before = tpm.read_pcrs()
    tpm.extend(0, b"grub")
    after = tpm.read_pcrs()
    assert after[0] != before[0]
    for idx in range(1, 8):
        assert after[idx] == before[idx]


def test_reset_pcrs_restores_empty() -> None:
    tpm = SimulatedTpm()
    tpm.extend(1, b"shim")
    tpm.reset_pcrs()
    assert tpm.read_pcrs()[1] == bytes(32)


def test_pcr_digest_is_stable() -> None:
    tpm = SimulatedTpm()
    first = pcr_digest(tpm.read_pcrs())
    second = pcr_digest(tpm.read_pcrs())
    assert first == second
    tpm.extend(7, b"cmdline")
    assert pcr_digest(tpm.read_pcrs()) != first
