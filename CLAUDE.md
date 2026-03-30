# upreason

A tool that answers "why was this package version released?" by scanning vulnerability databases and changelogs.

## Project overview

- **Language:** Python 3.12+
- **CLI framework:** argparse
- **HTTP client:** httpx
- **Package layout:** src/upreason/

## Development workflow

- **TDD (red/green):** Always write failing tests first, then implement code to make them pass.
- **Unit tests:** Must run fast with zero external dependencies (no network, no disk I/O). Use mocks/fakes for any external calls. Located in `tests/unit/`.
- **Integration tests:** Use recorded real data (cassettes/fixtures). Data must originate from actual API responses. Located in `tests/integration/`.
- **Test runner:** pytest

## Key data sources

- **OSV.dev API** — structured vulnerability advisories with affected/fixed version ranges
- **PyPI JSON API** — package metadata, per-version vulnerability info
- **GitHub Advisory Database** — via GitHub API (future)
- **Changelogs** — best-effort parsing from PyPI metadata links, sdist files, GitHub releases (future)

## Commands

```bash
# Run all tests
nox -s tests

# Run unit tests only
nox -s unit

# Run integration tests only
nox -s integration

# Pass extra args to pytest
nox -s unit -- -k test_name -v
```
