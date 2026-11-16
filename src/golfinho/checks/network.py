"""Read-only, cross-platform network inventory for the local host."""
import ipaddress
import json
import platform
import socket
import subprocess
from pathlib import Path


def _run(command, timeout=10):
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)


def _classify_dns_server(address):
    """Classify an address syntactically; this does not test reachability."""
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "invalid"
    if parsed.version == 6 and parsed in ipaddress.ip_network("fec0::/10"):
        return "deprecated_site_local"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_unspecified:
        return "unspecified"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_link_local:
        return "link_local"
    if parsed.is_private:
        return "private"
    if parsed.is_global:
        return "global"
    return "reserved"


def _linux_interface_kind(name, link_type=None):
    if name == "lo" or str(link_type or "").lower() == "loopback":
        return "loopback"
    virtual_path = Path("/sys/devices/virtual/net") / name
    device_path = Path("/sys/class/net") / name / "device"
    try:
        if virtual_path.exists():
            return "virtual"
        if device_path.exists():
            return "physical"
    except OSError:
        pass
    return "unknown"


def _add_dns_analysis(result):
    result["dns_server_analysis"] = [
        {"address": address, "classification": _classify_dns_server(address)}
        for address in result["dns_servers"]
    ]


def _empty_result(family):
    return {"platform": family, "interfaces": [], "gateways": [], "dns_servers": [],
            "sources": {}, "errors": [], "collection_mode": "read-only"}


def _record_source(result, name, status, detail=None):
    source = {"status": status}
    if detail:
        source["detail"] = detail
    result["sources"][name] = source


def _collect_linux():
    result = _empty_result("Linux")
    try:
        completed = _run(["ip", "-j", "address"])
        if completed.returncode:
            raise RuntimeError(completed.stderr.strip() or "ip address query failed")
        for item in json.loads(completed.stdout or "[]"):
            addresses = []
            for entry in item.get("addr_info") or []:
                if entry.get("local"):
                    addresses.append({"family": "IPv4" if entry.get("family") == "inet" else "IPv6",
                                      "address": entry["local"], "prefix_length": entry.get("prefixlen")})
            name = item.get("ifname", "unknown")
            result["interfaces"].append({"name": name,
                "kind": _linux_interface_kind(name, item.get("link_type")),
                "is_up": "UP" in (item.get("flags") or []), "mac": item.get("address"),
                "addresses": addresses})
        _record_source(result, "interfaces", "ok")
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        _record_source(result, "interfaces", "unavailable", str(error))
        result["errors"].append({"source": "interfaces", "error": str(error)})
        try:
            result["interfaces"] = [{"name": name, "kind": _linux_interface_kind(name),
                                     "is_up": None, "mac": None, "addresses": []}
                                    for _, name in socket.if_nameindex()]
        except OSError:
            pass

    try:
        routes4 = _run(["ip", "-j", "route", "show", "default"])
        routes6 = _run(["ip", "-6", "-j", "route", "show", "default"])
        if routes4.returncode or routes6.returncode:
            raise RuntimeError(routes4.stderr.strip() or routes6.stderr.strip() or "route query failed")
        for family, output in (("IPv4", routes4.stdout), ("IPv6", routes6.stdout)):
            for route in json.loads(output or "[]"):
                if route.get("gateway"):
                    result["gateways"].append({"family": family, "address": route["gateway"],
                                               "interface": route.get("dev")})
        _record_source(result, "routes", "ok")
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        _record_source(result, "routes", "unavailable", str(error))
        result["errors"].append({"source": "routes", "error": str(error)})

    try:
        nameservers = []
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
            fields = line.split("#", 1)[0].split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                nameservers.append(fields[1])
        result["dns_servers"] = list(dict.fromkeys(nameservers))
        _record_source(result, "dns", "ok", "read from /etc/resolv.conf")
        _add_dns_analysis(result)
    except OSError as error:
        _record_source(result, "dns", "unavailable", str(error))
        result["errors"].append({"source": "dns", "error": str(error)})
    return result


_WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$adapters = @(Get-NetAdapter -ErrorAction Stop | Select-Object @{Name='name';Expression={$_.Name}}, @{Name='description';Expression={$_.InterfaceDescription}}, @{Name='hardware_interface';Expression={$_.HardwareInterface}}, @{Name='status';Expression={$_.Status.ToString()}}, @{Name='mac';Expression={$_.MacAddress}}, @{Name='if_index';Expression={$_.ifIndex}})
$addresses = @(Get-NetIPAddress -ErrorAction Stop | Select-Object @{Name='interface_index';Expression={$_.InterfaceIndex}}, @{Name='family';Expression={$_.AddressFamily.ToString()}}, @{Name='address';Expression={$_.IPAddress}}, @{Name='prefix_length';Expression={$_.PrefixLength}})
$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Select-Object @{Name='family';Expression={if ($_.AddressFamily -eq 2) {'IPv4'} else {'IPv6'}}}, @{Name='address';Expression={$_.NextHop}}, @{Name='interface_index';Expression={$_.InterfaceIndex}})
$dns = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object { foreach ($server in $_.ServerAddresses) { [pscustomobject]@{interface_index=$_.InterfaceIndex; address=$server} } })
[pscustomobject]@{interfaces=$adapters; addresses=$addresses; routes=$routes; dns=$dns} | ConvertTo-Json -Depth 5 -Compress
"""


def _collect_windows():
    result = _empty_result("Windows")
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-Command", _WINDOWS_SCRIPT]
    try:
        completed = _run(command, timeout=15)
        if completed.returncode:
            raise RuntimeError(completed.stderr.strip() or "PowerShell network query failed")
        data = json.loads(completed.stdout or "{}")
        by_index = {}
        for item in data.get("interfaces") or []:
            index = item.get("if_index")
            description = str(item.get("description") or "")
            name = item.get("name", "unknown")
            hardware = item.get("hardware_interface")
            if "loopback" in (name + " " + description).lower():
                kind = "loopback"
            elif hardware is True:
                kind = "physical"
            elif hardware is False:
                kind = "virtual"
            else:
                kind = "unknown"
            by_index[index] = {"name": name, "kind": kind,
                "is_up": str(item.get("status", "")).lower() == "up",
                "mac": item.get("mac"), "addresses": []}
        for item in data.get("addresses") or []:
            target = by_index.get(item.get("interface_index"))
            if target and item.get("address"):
                target["addresses"].append({"family": item.get("family", "unknown"),
                    "address": item["address"], "prefix_length": item.get("prefix_length")})
        result["interfaces"] = list(by_index.values())
        _record_source(result, "interfaces", "ok")
        for route in data.get("routes") or []:
            address = route.get("address")
            if address and address not in {"0.0.0.0", "::"}:
                interface = next((entry["name"] for idx, entry in by_index.items()
                                  if idx == route.get("interface_index")), None)
                result["gateways"].append({"family": route.get("family", "unknown"),
                                           "address": address, "interface": interface})
        _record_source(result, "routes", "ok")
        result["dns_servers"] = list(dict.fromkeys(item["address"] for item in (data.get("dns") or [])
                                                   if item.get("address")))
        _record_source(result, "dns", "ok")
        _add_dns_analysis(result)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        for source in ("interfaces", "routes", "dns"):
            _record_source(result, source, "unavailable", str(error))
        result["errors"].append({"source": "windows_network", "error": str(error)})
    return result


def collect_network_info():
    """Collect local network configuration without remote scans or system changes."""
    system = platform.system().lower()
    if system == "linux":
        return _collect_linux()
    if system == "windows":
        return _collect_windows()
    result = _empty_result(platform.system() or "Unknown")
    for source in ("interfaces", "routes", "dns"):
        _record_source(result, source, "unsupported")
    return result
