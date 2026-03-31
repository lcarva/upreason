from unittest.mock import AsyncMock, patch

import pytest

from upreason.cli import main


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
