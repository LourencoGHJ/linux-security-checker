import ctypes
import platform


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def get_windows_info():
    return {
        "family": "Windows",
        "name": platform.system(),
        "version": platform.version(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "is_admin": is_admin(),
    }
