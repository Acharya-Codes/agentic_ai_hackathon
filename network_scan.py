import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

import psutil

from port_knowledge import hint_for

# Ports that matter most for home and IoT devices.
PROBE_PORTS = [21, 22, 23, 80, 554, 2323, 3389, 5555, 5900, 7547, 8000, 8080, 8888]
MAX_HOSTS = 254
CONNECT_TIMEOUT = 0.6

EXTRA_HINTS = {
    22: "SSH: encrypted remote login; fine if the password is strong",
    80: "HTTP: a web server or a device's web admin page",
    554: "RTSP video streaming, typical of IP cameras",
    8000: "Alternate web (HTTP) port, often a device or app admin page",
    8080: "Alternate web (HTTP) port, often a device or app admin page",
    8888: "Alternate web (HTTP) port, often a device or app admin page",
}


def port_hint(port):
    return hint_for(port) or EXTRA_HINTS.get(port, "")


def local_networks():
    """Private IPv4 networks this PC is connected to, as (interface, ip, network).
    Always limited to the /24 around your own address (at most 254 hosts)."""
    found = []
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            ip = ipaddress.ip_address(a.address)
            if not ip.is_private or ip.is_loopback or ip.is_link_local:
                continue
            net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
            if net.prefixlen < 24:
                net = ipaddress.ip_network(f"{a.address}/24", strict=False)
            found.append((name, a.address, net))
    return found


def _clean(text):
    """Banners come from other devices, so treat them as untrusted: plain ASCII only."""
    return "".join(ch for ch in text if 32 <= ord(ch) < 127).strip()[:60]


def probe_port(ip, port):
    """Return (port, banner) if the port accepts a connection, else None."""
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT) as s:
            s.settimeout(0.4)
            try:
                banner = _clean(s.recv(80).decode("utf-8", "replace"))
            except OSError:
                banner = ""
            return port, banner
    except OSError:
        return None


def _hostname(pool, ip):
    future = pool.submit(lambda: socket.gethostbyaddr(ip)[0])
    try:
        return future.result(timeout=2)
    except (FutureTimeout, OSError):
        return ""


def scan_network(net, my_ip, progress_cb=None):
    """Return a list of devices that have at least one risky port open."""
    hosts = [str(h) for h in net.hosts()][:MAX_HOSTS]
    found = {}
    group = 32
    with ThreadPoolExecutor(max_workers=128) as pool:
        for start in range(0, len(hosts), group):
            tasks = [(ip, p) for ip in hosts[start:start + group] for p in PROBE_PORTS]
            for (ip, _), res in zip(tasks, pool.map(lambda t: probe_port(*t), tasks)):
                if res:
                    port, banner = res
                    found.setdefault(ip, []).append(
                        {"port": port, "banner": banner, "hint": port_hint(port)}
                    )
            if progress_cb:
                progress_cb(min(1.0, (start + group) / len(hosts)))

        devices = []
        for ip in sorted(found, key=lambda a: ipaddress.ip_address(a)):
            devices.append({
                "id": len(devices),
                "ip": ip,
                "hostname": _hostname(pool, ip),
                "is_this_pc": ip == my_ip,
                "open_ports": sorted(found[ip], key=lambda p: p["port"]),
            })
    return devices