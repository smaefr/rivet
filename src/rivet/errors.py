class RivetError(Exception):
    """Base error for rivet."""


class TpmUnavailable(RivetError):
    """No TPM device and no simulator bound."""


class PcrMismatch(RivetError):
    """Live PCRs do not match the sealed baseline."""


class SealError(RivetError):
    """Sealed blob is corrupt or not authentic."""


class QuoteError(RivetError):
    """Attestation quote failed verification."""
