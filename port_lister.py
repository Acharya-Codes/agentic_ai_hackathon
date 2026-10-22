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
    """Return a list of dicts, one per listening TCP socket, sorted by port."""
    findings = []
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status != psutil.CONN_LISTEN:
            continue
        name, exe = process_info(conn.pid)
        findings.append({
            "port": conn.laddr.port,
            "address": conn.laddr.ip,
            "exposure": exposure(conn.laddr.ip),
            "pid": conn.pid,
            "process": name,
            "path": exe,
        })
    return sorted(findings, key=lambda f: f["port"])
def main():
    findings = list_listening_ports()
    print(f"Found {len(findings)} listening TCP sockets\n")
    print(f"{'PORT':<7}{'ADDRESS':<18}{'EXPOSURE':<19}{'PID':<8}PROCESS")
    print("-" * 70)
    for f in findings:
        print(f"{f['port']:<7}{f['address']:<18}{f['exposure']:<19}"
              f"{str(f['pid']):<8}{f['process']}")
if __name__ == "__main__":
    main()