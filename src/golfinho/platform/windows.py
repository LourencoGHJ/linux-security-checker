"""Windows host information adapter. Read-only; no system changes."""
import ctypes
import platform

def is_admin():
    """Return whether the current process has an elevated Windows token."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False

def get_windows_info():
    """Return Windows host details using the shared profile schema."""
    release = platform.release() or "unknown"
    return {
        "family": "Windows",
        "name": f"Windows {release}",
        "distribution": f"Windows {release}",
        "distribution_id": "windows",
        "version": platform.version() or "unknown",
        "kernel": release,
        "architecture": platform.machine() or "unknown",
        "hostname": platform.node() or "unknown",
        "is_admin": is_admin(),
    }
