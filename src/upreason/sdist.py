"""Extract package metadata from sdist archives."""

import email.parser
import io
import tarfile
from dataclasses import dataclass


@dataclass(frozen=True)
class PackageMetadata:
    name: str
    version: str


def extract_metadata(sdist_bytes: bytes) -> PackageMetadata:
    """Extract package name and version from an sdist .tar.gz archive.

    Looks for a PKG-INFO file inside the archive and parses the
    RFC 822-style metadata headers.
    """
    try:
        tar = tarfile.open(fileobj=io.BytesIO(sdist_bytes), mode="r:gz")
    except tarfile.TarError as err:
        raise ValueError("Not a valid .tar.gz archive") from err

    with tar:
        pkg_info_member = None
        for member in tar.getmembers():
            if member.name.endswith("/PKG-INFO") or member.name == "PKG-INFO":
                pkg_info_member = member
                break

        if pkg_info_member is None:
            raise ValueError("No PKG-INFO file found in sdist archive")

        f = tar.extractfile(pkg_info_member)
        if f is None:
            raise ValueError("Could not read PKG-INFO from archive")

        parser = email.parser.Parser()
        metadata = parser.parsestr(f.read().decode())

    name = metadata.get("Name")
    version = metadata.get("Version")

    if not name:
        raise ValueError("Name field missing from PKG-INFO")
    if not version:
        raise ValueError("Version field missing from PKG-INFO")

    return PackageMetadata(name=name, version=version)
