"""Linux user and group security checks."""

import grp
import pwd


PRIVILEGED_GROUPS = {"wheel", "sudo"}

NON_INTERACTIVE_UIDS = {65534}

NON_INTERACTIVE_SHELLS = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/nologin",
    "/usr/bin/nologin",
    "/bin/false",
    "/usr/bin/false",
}


def check_users():
    """Inspect local user accounts and privileged group membership."""

    accounts = pwd.getpwall()
    groups = grp.getgrall()

    uid_zero_accounts = [
        account.pw_name
        for account in accounts
        if account.pw_uid == 0
    ]

    privileged_group_members = {}

    for group in groups:
        if group.gr_name not in PRIVILEGED_GROUPS:
            continue

        members = set(group.gr_mem)

        for account in accounts:
            if account.pw_gid == group.gr_gid:
                members.add(account.pw_name)

        privileged_group_members[group.gr_name] = sorted(members)

    interactive_users = [
        account.pw_name
        for account in accounts
        if account.pw_uid >= 1000
        and account.pw_uid not in NON_INTERACTIVE_UIDS
        and account.pw_shell not in NON_INTERACTIVE_SHELLS
        and account.pw_shell
    ]

    return {
        "uid_zero_accounts": sorted(uid_zero_accounts),
        "privileged_group_members": privileged_group_members,
        "interactive_users": sorted(interactive_users),
    }
