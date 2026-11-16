REFERENCES = {
    "FIREWALL": [
        {
            "name": "UFW Documentation",
            "url": "https://help.ubuntu.com/community/UFW",
            "type": "Official documentation",
        },
        {
            "name": "nftables Documentation",
            "url": "https://www.netfilter.org/projects/nftables/",
            "type": "Official documentation",
        },
    ],
    "SERVICES": [
        {
            "name": "systemd Documentation",
            "url": "https://systemd.io/",
            "type": "Official documentation",
        },
        {
            "name": "MITRE ATT&CK - System Services",
            "url": "https://attack.mitre.org/techniques/T1569/",
            "type": "Security knowledge base",
        },
    ],
    "PERMISSIONS": [
        {
            "name": "CIS Benchmarks",
            "url": "https://www.cisecurity.org/cis-benchmarks",
            "type": "Security benchmark",
        },
        {
            "name": "Linux man-pages",
            "url": "https://man7.org/linux/man-pages/",
            "type": "Technical documentation",
        },
    ],
    "USERS": [
        {
            "name": "Linux man-pages - passwd",
            "url": "https://man7.org/linux/man-pages/man5/passwd.5.html",
            "type": "Technical documentation",
        },
        {
            "name": "MITRE ATT&CK - Valid Accounts",
            "url": "https://attack.mitre.org/techniques/T1078/",
            "type": "Security knowledge base",
        },
    ],
    "NETWORK": [
        {
            "name": "MITRE ATT&CK - Network Service Discovery",
            "url": "https://attack.mitre.org/techniques/T1046/",
            "type": "Security knowledge base",
        },
        {
            "name": "NIST National Vulnerability Database",
            "url": "https://nvd.nist.gov/",
            "type": "Vulnerability database",
        },
    ],
}


def get_references(category):
    return REFERENCES.get(category.upper(), [])


def get_all_references():
    return REFERENCES.copy()
