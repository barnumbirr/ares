"""Exception hierarchy for ares."""

from __future__ import annotations

class AresError(Exception):
    """Base exception for all ares errors."""

class ConnectionError(AresError):
    """Raised when the connection to the API fails."""

class TimeoutError(AresError):
    """Raised when the request to the API times out."""

class HTTPError(AresError):
    """Raised when the API returns an error HTTP status code.

    :param status_code: the HTTP status code.
    :param message: the (possibly truncated) response body.
    """

    def __init__(self, status_code: int, message: str = "") -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")
