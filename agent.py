import argparse
import os

from groq import Groq

import actions
from port_lister import list_listening_ports
from reasoner import assess_all

ACTIONABLE = ("block_with_firewall", "stop_service")


def ask_yes(prompt):
    return input(prompt).strip().lower() == "y"


def still_listening(port, pid):
    return any(f["port"] == port and f["pid"] == pid for f in list_listening_ports())


def handle(finding, assessment, dry_run):
    port, pid, name = finding["port"], finding["pid"], finding["process"]
    print("=" * 64)
    print(f"[{assessment['risk'].upper()}] Port {port} ({finding['exposure']}) - {name}")
    print(f"  What it is : {assessment['what_it_is']}")
    print(f"  Why        : {assessment['why']}")

    reason = actions.protection_reason(port, name)
    if reason:
        print(f"  Safety rule: {reason}, so the agent will not change it.")
        actions.log_action("skipped_protected", {"port": port, "process": name}, True, dry_run)
        return

    if assessment["action"] == "block_with_firewall":
        print("  Proposed   : block inbound connections to this port (reversible)")
        print("  Command    : " + " ".join(actions.block_command(port)))
        if not ask_yes("  Apply this change? [y/N]: "):
            actions.log_action("declined_block", {"port": port}, True, dry_run)
            print("  Skipped.")
            return
        ok, msg = actions.block_port(port, dry_run)
        print(f"  Result     : {'OK' if ok else 'FAILED'} - {msg}")
        if ok and not dry_run:
            print(f"  Verified   : firewall rule present = {actions.rule_exists(port)}")
            print("  Note       : the program may still listen on this PC; the firewall now")
            print("               stops OTHER devices reaching it. Test from your phone.")
            print(f"  Undo       : python agent.py --undo {port}")

    elif assessment["action"] == "stop_service":
        print(f"  Proposed   : stop the process {name} (PID {pid})")
        print("  WARNING    : this cannot be undone by the agent.")
        if not ask_yes("  Stop this process? Type y to confirm [y/N]: "):
            actions.log_action("declined_stop", {"pid": pid, "name": name}, True, dry_run)
            print("  Skipped.")
            return
        ok, msg = actions.stop_process(pid, name, dry_run)
        print(f"  Result     : {'OK' if ok else 'FAILED'} - {msg}")
        if ok and not dry_run:
            print(f"  Verified   : still listening = {still_listening(port, pid)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--undo", type=int, metavar="PORT")
    args = parser.parse_args()

    if args.undo is not None:
        if not args.dry_run and not actions.is_admin():
            print("Undo needs an Administrator terminal.")
            return
        ok, msg = actions.unblock_port(args.undo, args.dry_run)
        print(("Undone: " if ok else "Failed: ") + msg)
        return

    if not args.dry_run and not actions.is_admin():
        print("Not running as Administrator: real changes will fail.")
        print("Open an Administrator terminal, or use --dry-run to just preview.")
        return
    if "GROQ_API_KEY" not in os.environ:
        print("GROQ_API_KEY is not set in this terminal.")
        return

    findings = list_listening_ports()
    for i, f in enumerate(findings):
        f["id"] = i
    to_send = [
        {k: f[k] for k in ("id", "port", "address", "exposure", "process", "path")}
        for f in findings
    ]
    print(f"Scanning done: {len(findings)} listening ports. Asking the AI to assess them...")
    client = Groq(api_key=os.environ["GROQ_API_KEY"], max_retries=0)
    results = assess_all(client, to_send)

    order = {"high": 0, "medium": 1}
    todo = [
        f for f in findings
        if f["id"] in results
        and results[f["id"]]["action"] in ACTIONABLE
        and results[f["id"]]["risk"] != "low"
    ]
    todo.sort(key=lambda f: order[results[f["id"]]["risk"]])

    if not todo:
        print("\nNothing needs action. No medium or high risk ports were flagged.")
        return
    print(f"\n{len(todo)} item(s) need your decision."
          f"{' (DRY RUN: nothing will be changed)' if args.dry_run else ''}\n")
    for f in todo:
        handle(f, results[f["id"]], args.dry_run)
    print("\nDone. Every action is recorded in actions_log.jsonl")


if __name__ == "__main__":
    main()