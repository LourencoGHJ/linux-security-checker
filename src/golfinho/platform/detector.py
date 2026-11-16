"""Cross-platform host detection for the Golfinho research prototype."""
import platform
from datetime import datetime, timezone

from golfinho.platform.linux import get_linux_info
from golfinho.platform.windows import get_windows_info

def detect_platform():
    """Return a normalized, read-only host profile.

    This collects basic host metadata only. It does not decide whether the
    machine is secure or insecure.
    """
    system = platform.system().lower()
    if system == "linux":
        profile = get_linux_info()
    elif system == "windows":
        profile = get_windows_info()
    else:
        system_name = platform.system() or "Unknown"
        profile = {
            "family": system_name,
            "name": platform.platform() or "Unknown",
            "distribution": platform.platform() or "Unknown",
            "distribution_id": "unknown",
            "version": platform.version() or "unknown",
            "kernel": platform.release() or "unknown",
            "architecture": platform.machine() or "unknown",
            "hostname": platform.node() or "unknown",
            "is_admin": False,
        }
    profile["collected_at"] = datetime.now(timezone.utc).isoformat()
    profile["collection_mode"] = "read-only"
    return profile
