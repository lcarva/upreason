from typing import Any

import httpx

OSV_API_URL = "https://api.osv.dev/v1/query"


async def find_security_fixes(
    client: httpx.AsyncClient,
    package: str,
    version: str,
) -> list[dict[str, Any]]:
    """Find OSV advisories where the given version is listed as the fix.

    Queries the OSV API for all known vulnerabilities for the package,
    then filters for advisories where this exact version appears as a
    'fixed' event — meaning this version was released to address that
    vulnerability.
    """
    response = await client.post(
        OSV_API_URL,
        json={
            "package": {
                "name": package,
                "ecosystem": "PyPI",
            },
        },
    )
    response.raise_for_status()
    data = response.json()

    results = []
    for vuln in data.get("vulns", []):
        if _version_is_fix(vuln, version):
            results.append({
                "id": vuln["id"],
                "summary": vuln.get("summary", ""),
                "aliases": vuln.get("aliases", []),
            })

    return results


def _version_is_fix(vuln: dict[str, Any], version: str) -> bool:
    """Check if the given version appears as a 'fixed' event in any affected range."""
    for affected in vuln.get("affected", []):
        for range_entry in affected.get("ranges", []):
            for event in range_entry.get("events", []):
                if event.get("fixed") == version:
                    return True
    return False
