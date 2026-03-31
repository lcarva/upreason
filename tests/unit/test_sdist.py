import io
import tarfile

import pytest

from upreason.sdist import extract_metadata


def _make_sdist_tar_gz(pkg_info_content: str, prefix: str = "pkg-1.0.0") -> bytes:
    """Build a minimal sdist .tar.gz in memory containing a PKG-INFO file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=f"{prefix}/PKG-INFO")
        data = pkg_info_content.encode()
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestExtractMetadata:
    def test_extracts_name_and_version(self):
        sdist = _make_sdist_tar_gz(
            "Metadata-Version: 2.1\nName: requests\nVersion: 2.32.0\n"
        )
        result = extract_metadata(sdist)
        assert result.name == "requests"
        assert result.version == "2.32.0"

    def test_extracts_from_multiline_pkg_info(self):
        pkg_info = (
            "Metadata-Version: 2.1\n"
            "Name: six\n"
            "Version: 1.17.0\n"
            "Summary: Python 2 and 3 compatibility utilities\n"
            "Home-page: https://github.com/benjaminp/six\n"
            "Author: Benjamin Peterson\n"
        )
        sdist = _make_sdist_tar_gz(pkg_info, prefix="six-1.17.0")
        result = extract_metadata(sdist)
        assert result.name == "six"
        assert result.version == "1.17.0"

    def test_raises_on_missing_pkg_info(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="pkg-1.0.0/setup.py")
            data = b"from setuptools import setup; setup()"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        sdist = buf.getvalue()

        with pytest.raises(ValueError, match="PKG-INFO"):
            extract_metadata(sdist)

    def test_raises_on_missing_name(self):
        sdist = _make_sdist_tar_gz("Metadata-Version: 2.1\nVersion: 1.0.0\n")
        with pytest.raises(ValueError, match="Name"):
            extract_metadata(sdist)

    def test_raises_on_missing_version(self):
        sdist = _make_sdist_tar_gz("Metadata-Version: 2.1\nName: pkg\n")
        with pytest.raises(ValueError, match="Version"):
            extract_metadata(sdist)

    def test_raises_on_non_tar_gz(self):
        with pytest.raises((tarfile.TarError, ValueError)):
            extract_metadata(b"this is not a tarball")
