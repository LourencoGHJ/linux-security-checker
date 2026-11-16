"""Linux host information adapter. Read-only; no system changes."""
import os
import platform
from pathlib import Path

def _read_os_release():
    """Read os-release metadata without executing shell commands."""
    release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            release[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return release

def is_admin():
    """Return whether the current process has effective root privileges."""
    return hasattr(os, "geteuid") and os.geteuid() == 0

def get_linux_info():
    """Return Linux host details using the shared profile schema."""
    release = _read_os_release()
    distribution = release.get("PRETTY_NAME") or release.get("NAME") or "Linux"
    return {
        "family": "Linux",
        "name": distribution,
        "distribution": distribution,
        "distribution_id": release.get("ID", "unknown"),
        "version": release.get("VERSION_ID", "unknown"),
        "kernel": platform.release(),
        "architecture": platform.machine() or "unknown",
        "hostname": platform.node() or "unknown",
        "is_admin": is_admin(),
    }
