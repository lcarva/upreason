import argparse


def main():
    parser = argparse.ArgumentParser(
        prog="upreason",
        description="Find out why a package version was released.",
    )
    parser.add_argument("package", help="Package name (e.g. requests)")
    parser.add_argument("version", help="Version to inspect (e.g. 2.32.0)")
    parser.add_argument(
        "--from",
        dest="from_version",
        help="Previous version to compare against",
    )

    args = parser.parse_args()
    print(f"upreason: {args.package} {args.version} (not yet implemented)")
