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

def _print_network(network, output_format):
    if output_format == "json":
        print(json.dumps(network, indent=2, ensure_ascii=False))
        return
    print("GOLFINHO | NETWORK INVENTORY")
    print("=" * 32)
    print(f"Platform: {network.get('platform', 'unknown')}")
    print(f"Collection mode: {network.get('collection_mode', 'unknown')}")
    print()
    print("Interfaces:")
    for interface in network.get("interfaces", []):
        state = "up" if interface.get("is_up") is True else (
            "down" if interface.get("is_up") is False else "unknown"
        )
        print(f"  {interface.get('name', 'unknown')} [{state}]")
        if interface.get("mac"):
            print(f"    MAC: {interface['mac']}")
        for address in interface.get("addresses", []):
            prefix = address.get("prefix_length")
            suffix = f"/{prefix}" if prefix is not None else ""
            print(f"    {address.get('family', 'IP')}: {address.get('address')}{suffix}")
    print()
    print("Gateways:")
    for gateway in network.get("gateways", []):
        print(f"  {gateway.get('family')}: {gateway.get('address')} "
              f"({gateway.get('interface') or 'interface unknown'})")
    print()
    print("DNS servers:")
    for server in network.get("dns_servers", []):
        print(f"  {server}")
    print()
    print("Source status:")
    for source, details in network.get("sources", {}).items():
        print(f"  {source}: {details.get('status')}")
        if details.get("detail"):
            print(f"    {details['detail']}")
    for error in network.get("errors", []):
        print(f"  ERROR [{error.get('source')}]: {error.get('error')}")


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
    network_parser = subparsers.add_parser(
        "network", help="collect local network configuration (read-only)"
    )
    network_parser.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="output format (default: text)",
    )
    report_parser = subparsers.add_parser(
        "report", help="run the supported local checks and generate an HTML or JSON report"
    )
    report_parser.add_argument(
        "--format", choices=("html", "json"), default="html",
        help="report format (default: html)",
    )
    report_parser.add_argument(
        "--output-dir", default="reports",
        help="directory where the report is written (default: reports)",
    )
    dashboard_parser = subparsers.add_parser("dashboard", help="start the local live security dashboard")
    dashboard_parser.add_argument("--port", type=int, default=8765)
    dashboard_parser.add_argument("--interval", type=int, default=5,
                                  help="seconds between collections (default: 5; minimum: 1)")
    dashboard_parser.add_argument("--no-browser", action="store_true",
                                  help="do not open the browser automatically")
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
    if args.command == "network":
        try:
            from golfinho.checks.network import collect_network_info
            network = collect_network_info()
        except Exception as error:
            print(f"Golfinho could not collect network information: {error}", file=sys.stderr)
            return 1
        _print_network(network, args.format)
        return 0
    if args.command == "report":
        try:
            from golfinho.engine.scanner import run_security_scan
            from golfinho.reports.generator import generate_html_report, generate_json_report
            results = run_security_scan()
            generator = generate_html_report if args.format == "html" else generate_json_report
            destination = generator(results, output_dir=args.output_dir)
            print(f"Golfinho report generated: {destination}")
            print(f"Platform: {(results.get('platform') or {}).get('name', 'unknown')}")
            print(f"Execution errors: {len(results.get('errors', []))}")
            return 0
        except Exception as error:
            print(f"Golfinho could not generate the report: {error}", file=sys.stderr)
            return 1
    if args.command == "dashboard":
        try:
            from golfinho.interface.dashboard import serve_dashboard
            serve_dashboard(port=args.port, interval_seconds=args.interval,
                            open_browser=not args.no_browser)
            return 0
        except (OSError, ValueError) as error:
            print(f"Golfinho dashboard could not start: {error}", file=sys.stderr)
            return 1
    parser.error("unsupported command")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
