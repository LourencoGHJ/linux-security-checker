"""Command-line entry point for the Golfinho research prototype."""
import argparse
import json
import sys

from golfinho.platform.detector import detect_platform

def _print_profile(profile, output_format):
    if output_format == "json":
        print(json.dumps(profile, indent=2, ensure_ascii=False))
        return
    print("GOLFINHO | SYSTEM PROFILE")
    print("=" * 30)
    labels = (
        ("Operating system", "name"),
        ("Family", "family"),
        ("Distribution ID", "distribution_id"),
        ("Version", "version"),
        ("Kernel / release", "kernel"),
        ("Architecture", "architecture"),
        ("Hostname", "hostname"),
        ("Administrator", "is_admin"),
        ("Collected at (UTC)", "collected_at"),
        ("Collection mode", "collection_mode"),
    )
    for label, key in labels:
        value = profile.get(key, "unknown")
        if key == "is_admin":
            value = "yes" if value else "no"
        print(f"{label:24} {value}")

def build_parser():
    parser = argparse.ArgumentParser(
        prog="golfinho",
        description="Cross-platform, read-only system research prototype.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    profile_parser = subparsers.add_parser(
        "profile", help="collect basic operating-system and host metadata"
    )
    profile_parser.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="output format (default: text)",
    )
    return parser

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "profile":
        try:
            profile = detect_platform()
        except Exception as error:
            print(f"Golfinho could not collect the system profile: {error}", file=sys.stderr)
            return 1
        _print_profile(profile, args.format)
        return 0
    parser.error("unsupported command")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
