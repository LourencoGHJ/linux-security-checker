"""Read-only, cross-platform network inventory for the local host."""
import json
import platform
import socket
import subprocess
from pathlib import Path


def _run(command, timeout=10):
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)


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
            result["interfaces"].append({"name": item.get("ifname", "unknown"),
                "is_up": "UP" in (item.get("flags") or []), "mac": item.get("address"),
                "addresses": addresses})
        _record_source(result, "interfaces", "ok")
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as error:
        _record_source(result, "interfaces", "unavailable", str(error))
        result["errors"].append({"source": "interfaces", "error": str(error)})
        try:
            result["interfaces"] = [{"name": name, "is_up": None, "mac": None, "addresses": []}
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
    except OSError as error:
        _record_source(result, "dns", "unavailable", str(error))
        result["errors"].append({"source": "dns", "error": str(error)})
    return result


_WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$adapters = @(Get-NetAdapter -ErrorAction Stop | Select-Object @{Name='name';Expression={$_.Name}}, @{Name='status';Expression={$_.Status.ToString()}}, @{Name='mac';Expression={$_.MacAddress}}, @{Name='if_index';Expression={$_.ifIndex}})
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
            by_index[index] = {"name": item.get("name", "unknown"),
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
