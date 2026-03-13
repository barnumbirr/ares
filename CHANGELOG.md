# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-03-13

### Added

- Lazy pagination iterators (`*_iter()`) for all paginated endpoints.
- CLI tool (`ares-cli`) with full command coverage of the Vulnerability-Lookup API.

### Changed

- Dropped Python 3.9 support; minimum is now Python 3.10.
- CI and release workflows restructured (reusable CI, PyPI Trusted Publishers).

## [1.0.1] - 2026-02-11

### Fixed

- `CliRunner` compatibility with Click 8.2+.

## [1.0.0] - 2026-02-11

### Changed

- Complete rewrite targeting the [Vulnerability-Lookup](https://vulnerability.circl.lu) API.
- New `VulnLookup` client with context-manager support.
- Custom exception hierarchy (`AresError`, `HTTPError`, `ConnectionError`, `TimeoutError`).
