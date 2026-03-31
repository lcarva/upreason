"""Integration tests using recorded OSV API responses.

Fixtures were recorded from real OSV API calls on 2026-03-30.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from upreason.osv import find_security_fixes

FIXTURES_DIR = Path(__file__).parent


def _mock_client_with_fixture(fixture_name: str) -> AsyncMock:
    fixture_path = FIXTURES_DIR / fixture_name
    data = json.loads(fixture_path.read_text())

    mock_client = AsyncMock()
    mock_response = Mock()
    mock_response.json.return_value = data
    mock_response.raise_for_status = lambda: None
    mock_client.post.return_value = mock_response
    return mock_client


class TestRequestsPackage:
    """Tests using recorded OSV data for the 'requests' package."""

    @pytest.mark.asyncio
    async def test_version_2_32_0_fixes_cve_2024_35195(self):
        client = _mock_client_with_fixture("fixtures_requests.json")

        results = await find_security_fixes(client, "requests", "2.32.0")

        ids = {r["id"] for r in results}
        assert "GHSA-9wx4-h78v-vm56" in ids

        cve_aliases = set()
        for r in results:
            cve_aliases.update(r["aliases"])
        assert "CVE-2024-35195" in cve_aliases

    @pytest.mark.asyncio
    async def test_version_2_31_0_fixes_cve_2023_32681(self):
        client = _mock_client_with_fixture("fixtures_requests.json")

        results = await find_security_fixes(client, "requests", "2.31.0")

        ids = {r["id"] for r in results}
        assert "GHSA-j8r2-6x86-q33q" in ids

        cve_aliases = set()
        for r in results:
            cve_aliases.update(r["aliases"])
        assert "CVE-2023-32681" in cve_aliases

    @pytest.mark.asyncio
    async def test_version_2_3_0_fixes_multiple_cves(self):
        client = _mock_client_with_fixture("fixtures_requests.json")

        results = await find_security_fixes(client, "requests", "2.3.0")

        # 2.3.0 fixed multiple advisories (CVE-2014-1829 and CVE-2014-1830,
        # each with both a GHSA and PYSEC entry)
        ids = {r["id"] for r in results}
        assert len(ids) >= 2
        assert "GHSA-652x-xj99-gmcc" in ids
        assert "GHSA-cfj3-7x9c-4p3h" in ids

    @pytest.mark.asyncio
    async def test_version_with_no_fixes(self):
        client = _mock_client_with_fixture("fixtures_requests.json")

        # 2.29.0 is not listed as a fix version for any advisory
        results = await find_security_fixes(client, "requests", "2.29.0")

        assert results == []


class TestSixPackage:
    """Tests using recorded OSV data for 'six' (no known vulnerabilities)."""

    @pytest.mark.asyncio
    async def test_no_vulnerabilities(self):
        client = _mock_client_with_fixture("fixtures_six.json")

        results = await find_security_fixes(client, "six", "1.16.0")

        assert results == []
