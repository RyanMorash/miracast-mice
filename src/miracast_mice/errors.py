"""Errors raised by connection establishment."""


class MiceError(Exception):
    """Base error for this package."""


class ProtocolError(MiceError):
    """A message or attribute is not structurally valid."""


class DtlsError(MiceError):
    """The DTLS handshake or record layer failed."""


class FallbackRequired(MiceError):
    """Infrastructure setup stopped.

    The caller can fall back to Wi-Fi Direct. This package does not
    implement that path.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
