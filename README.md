# upreason

When a Python package publishes a new version, it's not always obvious *why*. Changelogs are inconsistent, and security fixes are often buried in release notes — or missing entirely.

upreason queries structured vulnerability databases to answer a specific question: **was this version released to fix a known security vulnerability?**

## Install

```bash
pip install upreason
```

## Usage

```bash
upreason requests 2.32.0
```

```
requests 2.32.0: 1 security fix(es)

  GHSA-9wx4-h78v-vm56 (CVE-2024-35195)
    Certificates not verified on redirects when using `verify=False`
```

```bash
upreason six 1.16.0
```

```
six 1.16.0: no known security fixes.
```

## Data sources

- [OSV.dev](https://osv.dev/) — aggregated vulnerability database covering PyPI and other ecosystems

## Development

Requires Python 3.12+ and [nox](https://nox.thea.codes/).

```bash
nox -s tests        # full test suite
nox -s unit         # fast unit tests (no network)
nox -s integration  # tests against recorded API data
```

## Limitations

upreason only detects **known, disclosed** vulnerabilities — those with an OSV/GHSA/CVE entry that names the fixed version. Security fixes that were never assigned an advisory will not be detected.
