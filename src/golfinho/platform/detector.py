import platform

from golfinho.platform.linux import get_linux_info
from golfinho.platform.windows import get_windows_info


def detect_platform():
    system = platform.system().lower()

    if system == "linux":
        return get_linux_info()

    if system == "windows":
        return get_windows_info()

    return {
        "family": "Unknown",
        "name": platform.platform(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "is_admin": False,
    }
