"""ares - Python wrapper around the Vulnerability-Lookup API."""

from __future__ import annotations

from .client import VulnLookup as VulnLookup
from .exceptions import AresError as AresError
from .exceptions import ConnectionError as ConnectionError
from .exceptions import HTTPError as HTTPError
from .exceptions import TimeoutError as TimeoutError

__title__ = "ares"
__version__ = "1.1.0"
__author__ = "Martin Simon <martin<at>simon.tf>"
__repo__ = "https://github.com/barnumbirr/ares"
__license__ = "Apache v2.0 License"

__all__ = [
    "VulnLookup",
    "AresError",
    "ConnectionError",
    "HTTPError",
    "TimeoutError",
]
