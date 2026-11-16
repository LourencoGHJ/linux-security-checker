import shutil
import subprocess


def run_command(command):
    """Execute a system command and capture its output safely."""
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None


def check_ufw():
    """Check whether UFW is installed and active."""
    if not shutil.which("ufw"):
        return "NOT_INSTALLED"

    result = run_command(["ufw", "status"])

    if result is None:
        return "ERROR"

    output = f"{result.stdout}\n{result.stderr}".lower()

    if "status: active" in output:
        return "ACTIVE"

    if "status: inactive" in output:
        return "INACTIVE"

    if "you need to be root" in output or "permission denied" in output:
        return "PERMISSION_DENIED"

    if result.returncode != 0:
        return "ERROR"

    return "UNKNOWN"


def check_firewalld():
    """Check whether firewalld is installed and running."""
    if not shutil.which("firewall-cmd"):
        return "NOT_INSTALLED"

    result = run_command(["firewall-cmd", "--state"])

    if result is None:
        return "ERROR"

    output = f"{result.stdout}\n{result.stderr}".lower()

    if result.returncode == 0 and "running" in output:
        return "ACTIVE"

    if "not running" in output:
        return "INACTIVE"

    if "permission denied" in output:
        return "PERMISSION_DENIED"

    return "ERROR"


def check_nftables():
    """Inspect the nftables ruleset without modifying it."""
    if not shutil.which("nft"):
        return "NOT_INSTALLED"

    result = run_command(["nft", "list", "ruleset"])

    if result is None:
        return "ERROR"

    output = f"{result.stdout}\n{result.stderr}".lower()

    if "operation not permitted" in output or "permission denied" in output:
        return "PERMISSION_DENIED"

    if result.returncode != 0:
        return "ERROR"

    if not result.stdout.strip():
        return "EMPTY_RULESET"

    if "managed by iptables-nft" in output:
        return "RULESET_PRESENT_IPTABLES_NFT"

    return "RULESET_PRESENT"


def check_nftables_service():
    """Check the systemd nftables service independently."""
    if not shutil.which("systemctl"):
        return "SYSTEMD_UNAVAILABLE"

    result = run_command(["systemctl", "is-active", "nftables"])

    if result is None:
        return "ERROR"

    status = result.stdout.strip().lower()

    if status == "active":
        return "ACTIVE"

    if status == "inactive":
        return "INACTIVE"

    if status:
        return status.upper()

    return "UNKNOWN"


def check_firewall():
    """Run all firewall-related checks."""
    return {
        "ufw": check_ufw(),
        "firewalld": check_firewalld(),
        "nftables": check_nftables(),
        "nftables_service": check_nftables_service(),
    }
