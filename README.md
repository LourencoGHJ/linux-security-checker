# Golfinho

**A cross-platform system reconnaissance and security research prototype built with Python.**

Golfinho is an experimental project focused on collecting local system and network information, normalizing observations across operating systems, and building a foundation for evidence-based security checks.

The project currently targets **Windows and Linux**. It is designed around a simple principle: collect what the host exposes, report what could not be collected, and keep observations separate from security conclusions.

> **Project status:** Early-stage research prototype. Golfinho is not a production endpoint protection platform, a complete vulnerability scanner, or a compliance certification tool.

---

## Contents

- [Project goals](#project-goals)
- [Current capabilities](#current-capabilities)
- [Platform support](#platform-support)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Example output](#example-output)
- [How collection works](#how-collection-works)
- [Architecture](#architecture)
- [Testing](#testing)
- [Security and privacy principles](#security-and-privacy-principles)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Contributing](#contributing)
- [License](#license)

## Project goals

Golfinho is being developed to explore how operating-system-specific information can be collected and represented through a consistent Python interface.

The main goals are to:

- Support Windows and Linux through isolated platform-specific collection logic.
- Normalize system and network observations into predictable data structures.
- Make collection failures and unsupported capabilities explicit.
- Keep collection read-only and avoid automatic remediation.
- Build small, independently testable security checks.
- Provide evidence that can support later investigation and reporting.

## Current capabilities

### 1. System profile

The `profile` command collects basic host metadata:

- Operating-system family and name.
- Distribution identifier where applicable.
- OS version and kernel/release.
- CPU architecture.
- Hostname.
- Whether the current process has administrative privileges.
- UTC collection timestamp.
- Collection mode.

### 2. Network inventory

The `network` command collects local network configuration where the operating system exposes it:

- Network interfaces and operational state.
- Interface type where it can be identified: physical, virtual, loopback, or unknown.
- MAC addresses.
- IPv4 and IPv6 addresses with prefix lengths.
- Default gateways and associated interfaces.
- Configured DNS server addresses.
- Basic DNS address classification, such as private, global, loopback, link-local, reserved, or deprecated IPv6 site-local.
- Per-source collection status and errors.

DNS classification is syntactic and based on address ranges. It does **not** test reachability, verify DNS responses, or establish that a resolver is trustworthy.

### 3. Experimental Linux checks

The repository also contains Linux-oriented checks for selected areas, including:

- Firewall configuration.
- User and account information.
- Services.
- File permissions.

The Linux checks remain experimental and platform-specific. Windows now has an initial read-only firewall inventory that collects profile settings, enabled-rule metadata and the Windows Firewall service state. Windows users, services and permissions checks remain unimplemented and are reported as skipped.

## Platform support

| Capability | Linux | Windows |
|---|---:|---:|
| System profile | Supported | Supported |
| Network interfaces and addresses | Supported | Supported |
| Default gateways | Supported | Supported |
| Configured DNS servers | Supported | Supported |
| Firewall inventory | Experimental Linux checks | Initial read-only inventory |
| User/account check | Experimental | Not implemented |
| Services check | Experimental | Not implemented |
| File-permission check | Experimental | Not implemented |

Support refers to the current implementation, not a guarantee that every operating-system version, configuration, or permission level exposes every data source.

## Requirements

- Python **3.10 or newer**.
- Linux: `iproute2` for interface and route collection.
- Windows: PowerShell and the built-in NetTCPIP networking cmdlets.
- No third-party runtime dependencies are currently required by the implemented profile and network commands.

Some collection sources may be unavailable depending on the operating system, environment, permissions, or installed system tools. Golfinho reports these conditions in its output.

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/LourencoGHJ/linux-security-checker.git
cd linux-security-checker
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Golfinho in editable mode:

```bash
python -m pip install -e .
```

## Usage

### Collect a system profile

Human-readable output:

```bash
python -m golfinho profile
```

JSON output:

```bash
python -m golfinho profile --format json
```

### Collect local network information

Human-readable output:

```bash
python -m golfinho network
```

JSON output:

```bash
python -m golfinho network --format json
```

The JSON format is intended to make the collected information easier to inspect, test, and consume in future tooling.

## Example output

A shortened example of the network inventory:

```json
{
  "platform": "Windows",
  "interfaces": [
    {
      "name": "Ethernet",
      "kind": "physical",
      "is_up": true,
      "mac": "00-11-22-33-44-55",
      "addresses": [
        {
          "family": "IPv4",
          "address": "192.168.1.100",
          "prefix_length": 24
        }
      ]
    }
  ],
  "gateways": [
    {
      "family": "IPv4",
      "address": "192.168.1.1",
      "interface": "Ethernet"
    }
  ],
  "dns_servers": [
    "192.168.1.1"
  ],
  "collection_mode": "read-only"
}
```

This is an illustrative, shortened example. Actual values depend on the host.

## How collection works

Golfinho uses platform-specific collection methods behind a shared interface:

- **Linux:** uses `iproute2` JSON output for interfaces and default routes, and reads `/etc/resolv.conf` for configured name servers.
- **Windows:** uses PowerShell with the built-in `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetRoute`, and `Get-DnsClientServerAddress` cmdlets.
- **Normalization:** maps platform-specific results into common fields so downstream code can work with a consistent structure.
- **Partial results:** records the status of individual sources and includes errors when a source cannot be queried.

On Linux, `/etc/resolv.conf` may point to a local stub resolver rather than list upstream DNS servers. On Windows, the reported DNS addresses are configured values; their availability is not tested.

## Architecture

The code is organized around separate responsibilities:

```text
src/
└── golfinho/
    ├── checks/
    │   ├── firewall.py
    │   ├── network.py
    │   ├── permissions.py
    │   ├── services.py
    │   └── users.py
    ├── engine/
    │   ├── evidence.py
    │   ├── rules.py
    │   ├── scanner.py
    │   └── severity.py
    ├── intelligence/
    │   ├── prompts.py
    │   └── references.py
    ├── platform/
    │   ├── detector.py
    │   ├── linux.py
    │   └── windows.py
    ├── reports/
    ├── interface/
    ├── main.py
    └── __main__.py
tests/
```

- `platform/` contains operating-system detection and host profile adapters.
- `checks/` contains focused collection and audit modules.
- `engine/` orchestrates checks and works with rules and evidence.
- `intelligence/` contains investigation prompts and technical references.
- `reports/` and `interface/` are reserved for reporting and user-interface development.
- `tests/` contains automated tests for supported behavior and failure conditions.

## Testing

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

The tests use mocked operating-system command output where appropriate, so platform-specific parsing and error handling can be tested without changing the host configuration.

Some legacy account-check tests require POSIX modules such as `grp` and `pwd`. They are skipped on Windows and are expected to run on supported POSIX systems.

## Security and privacy principles

1. **Read-only collection:** current profile and network inventory commands do not change system or network configuration.
2. **No remote scanning:** the network inventory describes the local host; it does not probe remote devices or ports.
3. **No automatic remediation:** Golfinho does not automatically modify firewall rules, accounts, services, or permissions.
4. **Evidence before conclusions:** collected observations are not automatically vulnerabilities.
5. **Explicit uncertainty:** unavailable tools, permission errors, and unsupported checks must remain visible.
6. **Platform isolation:** operating-system-specific behavior should stay behind dedicated adapters.
7. **Data minimization:** hostnames, MAC addresses, IP addresses, and other environment details can be sensitive. Review and redact collected output before publishing it or attaching it to an issue.

## Limitations and roadmap

Golfinho is being developed incrementally. Current and planned work includes:

- [x] Cross-platform host profile for Linux and Windows.
- [x] Read-only network inventory for Linux and Windows.
- [x] Normalized network output and source-level error reporting.
- [x] Initial interface and DNS address classification.
- [ ] Validate the latest network classification changes on both Windows and Linux.
- [ ] Expand automated tests on real Linux distributions, including Manjaro.
- [ ] Implement a read-only Windows Firewall inspection module.
- [ ] Improve evidence normalization and security findings.
- [ ] Develop structured reports and a more complete user interface.

Roadmap items are intentions, not claims of existing functionality.

## Contributing

This is an evolving research project. Contributions, bug reports, and technical feedback are welcome.

When proposing changes:

- Keep platform-specific code isolated.
- Prefer the Python standard library unless a dependency has a clear benefit.
- Include tests for normal results and collection failures.
- Do not silently convert missing data into a secure result.
- Document platform limitations and any additional privileges or tools required.

## License

This project is licensed under the [MIT License](LICENSE).
