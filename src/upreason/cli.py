import argparse
import asyncio
import sys
from typing import Any

import httpx

from upreason.osv import find_security_fixes as _find_security_fixes_async


def find_security_fixes(package: str, version: str) -> list[dict[str, Any]]:
    """Synchronous wrapper around the async OSV query."""

    async def _run():
        async with httpx.AsyncClient() as client:
            return await _find_security_fixes_async(client, package, version)

    return asyncio.run(_run())


def _format_results(package: str, version: str, fixes: list[dict[str, Any]]) -> str:
    if not fixes:
        return f"{package} {version}: no known security fixes."

    lines = [f"{package} {version}: {len(fixes)} security fix(es)\n"]
    for fix in fixes:
        aliases = ", ".join(fix["aliases"]) if fix["aliases"] else "no CVE alias"
        lines.append(f"  {fix['id']} ({aliases})")
        lines.append(f"    {fix['summary']}")
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="upreason",
        description="Find out why a package version was released.",
    )
    parser.add_argument("package", help="Package name (e.g. requests)")
    parser.add_argument("version", help="Version to inspect (e.g. 2.32.0)")

    args = parser.parse_args(argv)

    fixes = find_security_fixes(args.package, args.version)
    print(_format_results(args.package, args.version, fixes))
