import os
import platform
from pathlib import Path


def get_linux_info():
    release = {}

    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                release[key] = value.strip().strip('"')
    except OSError:
        pass

    return {
        "family": "Linux",
        "distribution": release.get("PRETTY_NAME", "Linux"),
        "distribution_id": release.get("ID", "unknown"),
        "version": release.get("VERSION_ID", "unknown"),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "is_admin": is_admin(),
    }


def is_admin():
    return hasattr(os, "geteuid") and os.geteuid() == 0
