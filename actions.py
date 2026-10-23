import ctypes
import json
import os
import subprocess
from datetime import datetime

import psutil

RULE_PREFIX = "PortGuardian-Block-"   # only rules with this name are ever touched
LOG_FILE = "actions_log.jsonl"

# Ports Windows itself depends on (RPC, file sharing). Never blocked by the agent.
PROTECTED_PORTS = {135, 139, 445}
# Core Windows processes. The agent will never stop these.
PROTECTED_PROCESSES = {
    "system", "system idle process", "lsass.exe", "wininit.exe",
    "services.exe", "csrss.exe", "winlogon.exe", "svchost.exe", "explorer.exe",
}


def protection_reason(port, process):
    """Why the agent must not change this, or None if it may propose a change."""
    if port in PROTECTED_PORTS:
        return f"port {port} is used by Windows itself"
    if (process or "").lower() in PROTECTED_PROCESSES:
        return f"{process} is a core Windows process"
    return None


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def log_action(action, detail, ok, dry_run=False):
    entry = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "detail": detail,
        "ok": ok,
        "dry_run": dry_run,
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _valid_port(port):
    return isinstance(port, int) and 1 <= port <= 65535


def rule_name(port):
    return f"{RULE_PREFIX}{port}"


def block_command(port):
    """The exact Windows Firewall command that blocks inbound TCP on a port."""
    return [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name(port)}", "dir=in", "action=block",
        "protocol=TCP", f"localport={port}",
    ]


def unblock_command(port):
    return [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name(port)}",
    ]


def _run(cmd, dry_run):
    if dry_run:
        return True, "DRY RUN - nothing was changed"
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def block_port(port, dry_run=False):
    if not _valid_port(port):
        return False, "invalid port number"
    if port in PROTECTED_PORTS:
        return False, f"port {port} is protected (Windows needs it); refusing"
    ok, msg = _run(block_command(port), dry_run)
    log_action("block_port", {"port": port}, ok, dry_run)
    return ok, msg


def unblock_port(port, dry_run=False):
    """Undo: removes only the rule this agent created for that port."""
    if not _valid_port(port):
        return False, "invalid port number"
    ok, msg = _run(unblock_command(port), dry_run)
    log_action("unblock_port", {"port": port}, ok, dry_run)
    return ok, msg


def rule_exists(port):
    """Verification for a firewall block: does our rule exist?"""
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name(port)}"],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def stop_process(pid, name, dry_run=False):
    """Stop a process. NOT reversible, so the agent asks for stronger confirmation."""
    if pid in (None, 0, 4, os.getpid()):
        return False, "refusing to stop that process"
    if (name or "").lower() in PROTECTED_PROCESSES:
        return False, f"{name} is a core Windows process; refusing"
    if dry_run:
        log_action("stop_process", {"pid": pid, "name": name}, True, True)
        return True, "DRY RUN - nothing was changed"
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5)
        ok, msg = True, f"stopped {name} (PID {pid})"
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as err:
        ok, msg = False, f"could not stop it: {err!r}"
    log_action("stop_process", {"pid": pid, "name": name}, ok)
    return ok, msg