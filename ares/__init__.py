"""ares - Python wrapper around the Vulnerability-Lookup API."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version

from .client import VulnLookup as VulnLookup
from .exceptions import AresError as AresError
from .exceptions import ConnectionError as ConnectionError
from .exceptions import HTTPError as HTTPError
from .exceptions import TimeoutError as TimeoutError

__title__ = "ares"
try:
    __version__ = version("ares")
except PackageNotFoundError:
    __version__ = "0.0.0"
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
