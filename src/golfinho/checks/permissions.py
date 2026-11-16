"""Audit permissions of critical Linux system files."""

import os
import stat


CRITICAL_FILES = {
    "/etc/passwd": "PUBLIC",
    "/etc/shadow": "SENSITIVE",
    "/etc/group": "PUBLIC",
    "/etc/gshadow": "SENSITIVE",
    "/etc/ssh/sshd_config": "CONFIG",
}


def inspect_file(path, category):
    """Inspect ownership and permissions without reading file contents."""

    try:
        file_stat = os.stat(path)
    except FileNotFoundError:
        return {
            "path": path,
            "status": "NOT_FOUND",
            "findings": ["File does not exist"],
        }
    except PermissionError:
        return {
            "path": path,
            "status": "PERMISSION_DENIED",
            "findings": ["Cannot inspect file metadata"],
        }
    except OSError:
        return {
            "path": path,
            "status": "ERROR",
            "findings": ["Could not inspect file"],
        }

    mode = stat.S_IMODE(file_stat.st_mode)
    findings = []

    if file_stat.st_uid != 0:
        findings.append("File is not owned by root")

    if mode & stat.S_IWGRP:
        findings.append("Group has write permission")

    if mode & stat.S_IWOTH:
        findings.append("Others have write permission")

    if category == "SENSITIVE":
        if mode & stat.S_IROTH:
            findings.append("Others can read sensitive file")

        if mode & stat.S_IXOTH:
            findings.append("Others can execute sensitive file")

    status = "REVIEW_REQUIRED" if findings else "OK"

    return {
        "path": path,
        "status": status,
        "owner_uid": file_stat.st_uid,
        "group_gid": file_stat.st_gid,
        "permissions": oct(mode),
        "findings": findings,
    }


def check_permissions():
    """Audit permissions of selected critical system files."""

    results = []

    for path, category in CRITICAL_FILES.items():
        results.append(inspect_file(path, category))

    return results
