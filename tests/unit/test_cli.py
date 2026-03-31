import io
import tarfile
from unittest.mock import AsyncMock, patch

import pytest

from upreason.cli import main
from upreason.sdist import PackageMetadata


class TestCLI:
    def test_security_fixes_found(self, capsys):
        mock_fixes = [
            {
                "id": "GHSA-9wx4-h78v-vm56",
                "summary": "Remote code execution vulnerability",
                "aliases": ["CVE-2024-35195"],
            },
        ]

        with patch("upreason.cli.find_security_fixes", return_value=mock_fixes) as mock_find:
            main(["requests", "2.32.0"])

        mock_find.assert_called_once_with("requests", "2.32.0")

        captured = capsys.readouterr()
        assert "GHSA-9wx4-h78v-vm56" in captured.out
        assert "CVE-2024-35195" in captured.out
        assert "Remote code execution vulnerability" in captured.out

    def test_no_security_fixes(self, capsys):
        with patch("upreason.cli.find_security_fixes", return_value=[]):
            main(["requests", "2.29.0"])

        captured = capsys.readouterr()
        assert "no known security fixes" in captured.out.lower()

    def test_multiple_fixes(self, capsys):
        mock_fixes = [
            {
                "id": "GHSA-aaaa",
                "summary": "Bug A",
                "aliases": ["CVE-2024-11111"],
            },
            {
                "id": "GHSA-bbbb",
                "summary": "Bug B",
                "aliases": ["CVE-2024-22222"],
            },
        ]

        with patch("upreason.cli.find_security_fixes", return_value=mock_fixes):
            main(["somepackage", "1.0.0"])

        captured = capsys.readouterr()
        assert "GHSA-aaaa" in captured.out
        assert "GHSA-bbbb" in captured.out

    def test_fix_with_no_aliases(self, capsys):
        mock_fixes = [
            {
                "id": "GHSA-xxxx",
                "summary": "Some issue",
                "aliases": [],
            },
        ]

        with patch("upreason.cli.find_security_fixes", return_value=mock_fixes):
            main(["pkg", "1.0.0"])

        captured = capsys.readouterr()
        assert "GHSA-xxxx" in captured.out
        assert "Some issue" in captured.out


class TestCLIHelp:
    def test_help_includes_examples(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "examples:" in captured.out.lower()
        assert "# Check a specific package version" in captured.out
        assert "upreason requests 2.32.0" in captured.out
        assert "# Check an sdist archive" in captured.out
        assert ".tar.gz" in captured.out


class TestCLISdist:
    def test_sdist_extracts_and_queries(self, capsys, tmp_path):
        """Given a .tar.gz path, extract metadata and query for fixes."""
        sdist_path = tmp_path / "pkg-1.0.0.tar.gz"
        sdist_path.write_bytes(b"fake")

        mock_metadata = PackageMetadata(name="requests", version="2.32.0")
        mock_fixes = [
            {
                "id": "GHSA-9wx4-h78v-vm56",
                "summary": "Vulnerability fix",
                "aliases": ["CVE-2024-35195"],
            },
        ]

        with (
            patch("upreason.cli.extract_metadata", return_value=mock_metadata) as mock_extract,
            patch("upreason.cli.find_security_fixes", return_value=mock_fixes) as mock_find,
        ):
            main([str(sdist_path)])

        mock_extract.assert_called_once()
        mock_find.assert_called_once_with("requests", "2.32.0")

        captured = capsys.readouterr()
        assert "GHSA-9wx4-h78v-vm56" in captured.out

    def test_sdist_no_fixes(self, capsys, tmp_path):
        sdist_path = tmp_path / "six-1.17.0.tar.gz"
        sdist_path.write_bytes(b"fake")

        mock_metadata = PackageMetadata(name="six", version="1.17.0")

        with (
            patch("upreason.cli.extract_metadata", return_value=mock_metadata),
            patch("upreason.cli.find_security_fixes", return_value=[]),
        ):
            main([str(sdist_path)])

        captured = capsys.readouterr()
        assert "no known security fixes" in captured.out.lower()

    def test_sdist_file_not_found(self, tmp_path):
        missing = tmp_path / "nope.tar.gz"

        with pytest.raises(SystemExit):
            main([str(missing)])
