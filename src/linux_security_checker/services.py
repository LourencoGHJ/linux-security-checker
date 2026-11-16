"""Linux systemd service security checks."""

import shutil
import subprocess


def run_systemctl(command):
    """Execute a systemctl command safely."""
    try:
        return subprocess.run(
            ["systemctl", *command],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None


def parse_service_units(output):
    """Extract service unit names from systemctl list output."""
    services = []

    for line in output.splitlines():
        parts = line.split()

        if parts and parts[0].endswith(".service"):
            services.append(parts[0])

    return sorted(set(services))


def check_services():
    """Inspect running, enabled and failed systemd services."""

    if not shutil.which("systemctl"):
        return {
            "status": "SYSTEMD_UNAVAILABLE",
            "running_services": [],
            "enabled_services": [],
            "failed_services": [],
        }

    commands = {
        "running_services": [
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ],
        "enabled_services": [
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ],
        "failed_services": [
            "list-units",
            "--type=service",
            "--state=failed",
            "--no-legend",
            "--no-pager",
        ],
    }

    results = {
        "status": "OK",
        "running_services": [],
        "enabled_services": [],
        "failed_services": [],
    }

    for category, command in commands.items():
        result = run_systemctl(command)

        if result is None or result.returncode != 0:
            results["status"] = "PARTIAL"
            continue

        results[category] = parse_service_units(result.stdout)

    return results
