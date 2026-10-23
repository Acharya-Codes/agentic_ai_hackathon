import psutil

def exposure(ip):
    """Loopback addresses are only reachable from this machine itself.
    Anything else (0.0.0.0, ::, or a LAN IP) can be reached from the network."""
    if ip in ("127.0.0.1", "::1"):
        return "local only"
    return "NETWORK-REACHABLE"


def process_info(pid):
    """Return (name, exe_path) for a PID, handling processes we can't inspect."""
    if pid is None:
        return "unknown", "unknown"
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            exe = "access denied"
        return name, exe
    except psutil.NoSuchProcess:
        return "process ended", ""
    except psutil.AccessDenied:
        return "access denied", "access denied"


def list_listening_ports():
    """Return a list of dicts, one per (port, process), sorted by port."""
    merged = {}
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status != psutil.CONN_LISTEN:
            continue
        key = (conn.laddr.port, conn.pid)
        if key in merged:
            if conn.laddr.ip not in merged[key]["addresses"]:
                merged[key]["addresses"].append(conn.laddr.ip)
            continue
        name, exe = process_info(conn.pid)
        merged[key] = {
            "port": conn.laddr.port,
            "addresses": [conn.laddr.ip],
            "pid": conn.pid,
            "process": name,
            "path": exe,
        }

    findings = []
    for m in merged.values():
        addrs = m.pop("addresses")
        m["address"] = ", ".join(addrs)
        reachable = any(exposure(a) == "NETWORK-REACHABLE" for a in addrs)
        m["exposure"] = "NETWORK-REACHABLE" if reachable else "local only"
        findings.append(m)
    return sorted(findings, key=lambda f: f["port"])


def main():
    findings = list_listening_ports()
    print(f"Found {len(findings)} listening TCP ports\n")
    print(f"{'PORT':<7}{'ADDRESS':<22}{'EXPOSURE':<19}{'PID':<8}PROCESS")
    print("-" * 74)
    for f in findings:
        print(f"{f['port']:<7}{f['address']:<22}{f['exposure']:<19}"
              f"{str(f['pid']):<8}{f['process']}")


if __name__ == "__main__":
    main()