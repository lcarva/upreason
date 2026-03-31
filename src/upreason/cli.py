import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

import httpx

from upreason.osv import find_security_fixes as _find_security_fixes_async
from upreason.sdist import extract_metadata


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


def _is_sdist_path(arg: str) -> bool:
    return arg.endswith(".tar.gz") and Path(arg).is_file()


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="upreason",
        description="Find out why a package version was released.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # Check a specific package version
  upreason requests 2.32.0

  # Check an sdist archive
  upreason ./downloads/pkg-1.0.0.tar.gz""",
    )
    parser.add_argument(
        "args",
        nargs="+",
        metavar="TARGET",
        help="PACKAGE VERSION or path to an sdist .tar.gz",
    )

    parsed = parser.parse_args(argv)

    if len(parsed.args) == 1 and parsed.args[0].endswith(".tar.gz"):
        sdist_path = Path(parsed.args[0])
        if not sdist_path.is_file():
            parser.error(f"sdist not found: {sdist_path}")
        metadata = extract_metadata(sdist_path.read_bytes())
        package, version = metadata.name, metadata.version
    elif len(parsed.args) == 2:
        package, version = parsed.args
    else:
        parser.error("expected PACKAGE VERSION or a single sdist .tar.gz path")

    fixes = find_security_fixes(package, version)
    print(_format_results(package, version, fixes))
