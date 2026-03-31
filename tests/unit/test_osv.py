from unittest.mock import AsyncMock, Mock, patch

import pytest

from upreason.osv import find_security_fixes


@pytest.fixture
def osv_response_with_fix():
    """OSV response where the queried version is listed as a fix."""
    return {
        "vulns": [
            {
                "id": "GHSA-1234-5678-abcd",
                "summary": "Remote code execution in example-package",
                "details": "A vulnerability allows remote code execution.",
                "aliases": ["CVE-2024-12345"],
                "affected": [
                    {
                        "package": {
                            "name": "example-package",
                            "ecosystem": "PyPI",
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "1.2.0"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }


@pytest.fixture
def osv_response_no_match():
    """OSV response where the queried version is NOT a fix version."""
    return {
        "vulns": [
            {
                "id": "GHSA-1234-5678-abcd",
                "summary": "Remote code execution in example-package",
                "details": "A vulnerability allows remote code execution.",
                "aliases": ["CVE-2024-12345"],
                "affected": [
                    {
                        "package": {
                            "name": "example-package",
                            "ecosystem": "PyPI",
                        },
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "1.2.0"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }


@pytest.fixture
def osv_response_empty():
    """OSV response with no vulnerabilities."""
    return {"vulns": []}


@pytest.fixture
def osv_response_no_vulns_key():
    """OSV response when package has no known vulnerabilities at all."""
    return {}


class TestFindSecurityFixes:
    @pytest.mark.asyncio
    async def test_version_is_fix(self, osv_response_with_fix):
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.json.return_value = osv_response_with_fix
        mock_response.raise_for_status = lambda: None
        mock_client.post.return_value = mock_response

        results = await find_security_fixes(
            mock_client, "example-package", "1.2.0"
        )

        assert len(results) == 1
        assert results[0]["id"] == "GHSA-1234-5678-abcd"
        assert results[0]["aliases"] == ["CVE-2024-12345"]
        assert results[0]["summary"] == "Remote code execution in example-package"

    @pytest.mark.asyncio
    async def test_version_is_not_fix(self, osv_response_no_match):
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.json.return_value = osv_response_no_match
        mock_response.raise_for_status = lambda: None
        mock_client.post.return_value = mock_response

        results = await find_security_fixes(
            mock_client, "example-package", "1.1.0"
        )

        assert results == []

    @pytest.mark.asyncio
    async def test_no_vulnerabilities(self, osv_response_empty):
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.json.return_value = osv_response_empty
        mock_response.raise_for_status = lambda: None
        mock_client.post.return_value = mock_response

        results = await find_security_fixes(
            mock_client, "example-package", "1.0.0"
        )

        assert results == []

    @pytest.mark.asyncio
    async def test_no_vulns_key(self, osv_response_no_vulns_key):
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.json.return_value = osv_response_no_vulns_key
        mock_response.raise_for_status = lambda: None
        mock_client.post.return_value = mock_response

        results = await find_security_fixes(
            mock_client, "example-package", "2.0.0"
        )

        assert results == []

    @pytest.mark.asyncio
    async def test_multiple_advisories_some_match(self):
        """When multiple advisories exist, only return ones fixed by this version."""
        response_data = {
            "vulns": [
                {
                    "id": "GHSA-aaaa",
                    "summary": "Bug A",
                    "aliases": [],
                    "affected": [
                        {
                            "package": {"name": "pkg", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "1.0.0"},
                                        {"fixed": "2.0.0"},
                                    ],
                                }
                            ],
                        }
                    ],
                },
                {
                    "id": "GHSA-bbbb",
                    "summary": "Bug B",
                    "aliases": ["CVE-2024-99999"],
                    "affected": [
                        {
                            "package": {"name": "pkg", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "1.0.0"},
                                        {"fixed": "1.5.0"},
                                    ],
                                }
                            ],
                        }
                    ],
                },
            ]
        }

        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.json.return_value = response_data
        mock_response.raise_for_status = lambda: None
        mock_client.post.return_value = mock_response

        results = await find_security_fixes(mock_client, "pkg", "2.0.0")

        assert len(results) == 1
        assert results[0]["id"] == "GHSA-aaaa"

    @pytest.mark.asyncio
    async def test_calls_correct_osv_endpoint(self):
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.json.return_value = {"vulns": []}
        mock_response.raise_for_status = lambda: None
        mock_client.post.return_value = mock_response

        await find_security_fixes(mock_client, "requests", "2.32.0")

        mock_client.post.assert_called_once_with(
            "https://api.osv.dev/v1/query",
            json={
                "package": {
                    "name": "requests",
                    "ecosystem": "PyPI",
                },
            },
        )
