"""Integration tests for sdist metadata extraction using real PKG-INFO data.

PKG-INFO fixtures were captured from real sdist archives downloaded from PyPI
on 2026-03-30.
"""

import io
import tarfile
from pathlib import Path

from upreason.sdist import extract_metadata

FIXTURES_DIR = Path(__file__).parent


def _build_sdist(pkg_info_path: Path, prefix: str) -> bytes:
    """Build a .tar.gz in memory using a real PKG-INFO fixture."""
    pkg_info_data = pkg_info_path.read_bytes()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=f"{prefix}/PKG-INFO")
        info.size = len(pkg_info_data)
        tar.addfile(info, io.BytesIO(pkg_info_data))
    return buf.getvalue()


class TestRequestsSdist:
    """requests 2.32.0 — a version released to fix CVE-2024-35195."""

    def test_extracts_name(self):
        sdist = _build_sdist(
            FIXTURES_DIR / "pkginfo_requests_2_32_0.txt",
            prefix="requests-2.32.0",
        )
        result = extract_metadata(sdist)
        assert result.name == "requests"

    def test_extracts_version(self):
        sdist = _build_sdist(
            FIXTURES_DIR / "pkginfo_requests_2_32_0.txt",
            prefix="requests-2.32.0",
        )
        result = extract_metadata(sdist)
        assert result.version == "2.32.0"


class TestSixSdist:
    """six 1.17.0 — a version with no known vulnerabilities."""

    def test_extracts_name(self):
        sdist = _build_sdist(
            FIXTURES_DIR / "pkginfo_six_1_17_0.txt",
            prefix="six-1.17.0",
        )
        result = extract_metadata(sdist)
        assert result.name == "six"

    def test_extracts_version(self):
        sdist = _build_sdist(
            FIXTURES_DIR / "pkginfo_six_1_17_0.txt",
            prefix="six-1.17.0",
        )
        result = extract_metadata(sdist)
        assert result.version == "1.17.0"
