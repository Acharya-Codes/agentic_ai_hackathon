import json
import os

import streamlit as st
from groq import Groq

import actions
from port_knowledge import guide_for, hint_for
from port_lister import list_listening_ports
from reasoner import assess_all
from score import compute_score, grade
from chatbot import HOST_SUGGESTIONS, host_context, render_chat
from session_persistence import (
    clear_all_reports,
    persist_session_state,
    restore_session_state,
)

ACTIONABLE = ("block_with_firewall", "stop_service")

st.set_page_config(page_title="App", page_icon="🛡️", layout="wide")
restore_session_state()

# ---------- session state (survives button clicks) ----------
for key, default in [("findings", None), ("results", {}), ("before", None),
                     ("applied", {}), ("declined", set())]:
    if key not in st.session_state:
        st.session_state[key] = default


def scan_and_assess():
    findings = list_listening_ports()
    for i, f in enumerate(findings):
        f["id"] = i
    to_send = [
        {k: f[k] for k in ("id", "port", "address", "exposure", "process", "path")}
        for f in findings
    ]
    client = (Groq(api_key=os.environ["GROQ_API_KEY"], max_retries=0)
              if "GROQ_API_KEY" in os.environ else None)
    results = assess_all(client, to_send)
    st.session_state.findings = findings
    st.session_state.results = results
    st.session_state.applied = {}
    st.session_state.declined = set()
    st.session_state.before = compute_score(findings, results, set())
    persist_session_state()


def render_footer():
    st.markdown("---")
    st.markdown("[View this project on GitHub](https://github.com/Acharya-Codes/agentic_ai_hackathon)")


@st.dialog("Clear reports and return home?")
def confirm_clear_reports():
    st.warning(
        "This will clear the current PC and network scan reports, chat histories, "
        "and approval status. Do you want to continue?"
    )
    yes, no = st.columns(2)
    if yes.button("Yes, clear reports", type="primary", key="clear_reports_yes"):
        clear_all_reports()
        st.rerun()
    if no.button("No, keep reports", key="clear_reports_no"):
        st.rerun()


# ---------- header and sidebar ----------
st.title("🛡️ GuberoAI")
st.caption("An AI agent that finds risky open ports on this PC, explains them in plain "
           "language, and fixes them only with your approval.")

if (st.session_state.get("findings") is not None
        or st.session_state.get("net_devices") is not None):
    if st.button("⬅️ Back to home"):
        confirm_clear_reports()

admin = actions.is_admin()
st.sidebar.header("Controls")
dry = st.sidebar.checkbox("Dry run (preview only, change nothing)", value=not admin,
                          key="dry_run")
st.sidebar.write(f"Running as Administrator: **{'yes' if admin else 'no'}**")
if not admin and not dry:
    st.sidebar.warning("Real changes will fail without Administrator rights.")
key_ok = "GROQ_API_KEY" in os.environ
if not key_ok:
    st.sidebar.info("GROQ_API_KEY is not set; the scan will use rule-based assessments.")

if st.sidebar.button("🔍 Scan & assess", type="primary"):
    with st.spinner("Scanning this PC and assessing each port..."):
        scan_and_assess()

if st.session_state.findings is None:
    st.info("Click **Scan & assess** in the sidebar to begin.")
    render_footer()
    st.stop()

findings = st.session_state.findings
results = st.session_state.results
applied = st.session_state.applied
rule_fallbacks = sum(
    1 for f in findings
    if f["exposure"] == "NETWORK-REACHABLE"
    and results.get(f["id"], {}).get("source") == "rule"
)
if rule_fallbacks:
    st.info(f"Rule-based fallback assessments were used for {rule_fallbacks} "
            "network-reachable port(s) because AI assessment was unavailable or rate-limited.")

# ---------- score ----------
mitigated = {port for port, info in applied.items() if info["real"]}
now = compute_score(findings, results, mitigated)
before = st.session_state.before
m1, m2, m3 = st.columns(3)
m1.metric("Security score", f"{now}/100", delta=(now - before) if now != before else None)
m2.metric("Rating", grade(now))
m3.metric("Ports scanned", len(findings))
if dry:
    st.warning("Dry run is ON: approvals only preview the change. Untick it in the sidebar "
               "for real changes.")

# ---------- split findings into actionable / protected ----------
needs_action, protected = [], []
for f in findings:
    a = results.get(f["id"])
    if not a or a["risk"] == "low" or a["action"] not in ACTIONABLE:
        continue
    reason = actions.protection_reason(f["port"], f["process"])
    if reason:
        protected.append((f, a, reason))
    else:
        needs_action.append((f, a))


def still_listening(port, pid):
    return any(x["port"] == port and x["pid"] == pid for x in list_listening_ports())


def render_card(f, a):
    port, pid, name = f["port"], f["pid"], f["process"]
    done = applied.get(port)
    badge = {"high": "🔴 HIGH", "medium": "🟠 MEDIUM"}[a["risk"]]
    with st.container(border=True):
        st.subheader(f"{badge}  ·  Port {port}  ·  {name}")
        st.write(f"**What it is:** {a['what_it_is']}")
        st.write(f"**Why it matters:** {a['why']}")
        hint = hint_for(port)
        if hint:
            st.caption(f"Knowledge base: {hint}")

        if done:
            st.success(done["message"])
            if done["kind"] == "block" and done["real"]:
                if st.button("↩ Undo this change", key=f"undo{f['id']}"):
                    ok, msg = actions.unblock_port(port)
                    if ok:
                        applied.pop(port, None)
                        persist_session_state()
                        st.rerun()
                    st.error(msg)
            return

        if a["action"] == "block_with_firewall":
            st.write("**Proposed:** block inbound connections to this port (reversible)")
            st.code(" ".join(actions.block_command(port)), language="bash")
            col1, col2 = st.columns(2)
            if col1.button("✅ Approve block", key=f"ok{f['id']}"):
                ok, msg = actions.block_port(port, dry)
                if ok:
                    if dry:
                        text = "Dry run: this change was previewed only. Nothing was changed."
                    else:
                        text = ("Blocked. Firewall rule present: "
                                f"{actions.rule_exists(port)}. Other devices can no longer "
                                "reach this port.")
                    applied[port] = {"kind": "block", "real": not dry, "message": text}
                    persist_session_state()
                    st.rerun()
                st.error(f"Failed: {msg}")
            if col2.button("❌ Decline", key=f"no{f['id']}"):
                actions.log_action("declined_block", {"port": port}, True, dry)
                st.session_state.declined.add(port)
                persist_session_state()
                st.rerun()

        elif a["action"] == "stop_service":
            st.write(f"**Proposed:** stop the process **{name}** (PID {pid})")
            st.warning("This cannot be undone by the agent.")
            sure = st.checkbox("I understand this cannot be undone", key=f"sure{f['id']}")
            col1, col2 = st.columns(2)
            if col1.button("✅ Approve stop", key=f"ok{f['id']}", disabled=not sure):
                ok, msg = actions.stop_process(pid, name, dry)
                if ok:
                    if dry:
                        text = "Dry run: nothing was changed."
                    else:
                        text = (f"Stopped {name}. Still listening: "
                                f"{still_listening(port, pid)}.")
                    applied[port] = {"kind": "stop", "real": not dry, "message": text}
                    persist_session_state()
                    st.rerun()
                st.error(f"Failed: {msg}")
            if col2.button("❌ Decline", key=f"no{f['id']}"):
                actions.log_action("declined_stop", {"pid": pid, "name": name}, True, dry)
                st.session_state.declined.add(port)
                persist_session_state()
                st.rerun()


# ---------- findings that need a decision ----------
visible = [(f, a) for f, a in needs_action if f["port"] not in st.session_state.declined]
st.header(f"Needs your decision ({len(visible)})")
if not visible:
    st.success("Nothing else needs action.")
for f, a in visible:
    render_card(f, a)

# ---------- protected items: guided steps only ----------
if protected:
    st.header("Flagged, but the agent will not change these")
    for f, a, reason in protected:
        with st.container(border=True):
            st.subheader(f"🟠 Port {f['port']} · {f['process']}")
            st.write(f"**What it is:** {a['what_it_is']}")
            st.write(f"**Why it matters:** {a['why']}")
            st.info(f"Safety rule: {reason}, so the agent leaves it alone.")
            guide = guide_for(f["port"])
            if guide:
                st.write(f"**Suggested fix (do this yourself):** {guide}")

# ---------- full table ----------
with st.expander("All scanned ports"):
    rows = []
    for f in findings:
        a = results.get(f["id"])
        rows.append({
            "Port": f["port"],
            "Process": f["process"],
            "Exposure": f["exposure"],
            "Risk": a["risk"] if a else "not assessed",
            "AI suggestion": a["action"] if a else "",
            "Assessment": ("Rule-based" if a and a.get("source") == "rule"
                           else "Cached AI" if a and a.get("source") == "cache"
                           else "AI" if a else "not assessed"),
            "Fixed": "yes" if f["port"] in mitigated else "",
        })
    st.dataframe(rows, hide_index=True)

# ---------- action log ----------
with st.expander("Action log"):
    if os.path.exists(actions.LOG_FILE):
        with open(actions.LOG_FILE, encoding="utf-8") as fh:
            lines = [json.loads(line) for line in fh if line.strip()][-15:]
        st.dataframe(
            [{"Time": e["time"], "Action": e["action"], "Detail": json.dumps(e["detail"]),
              "OK": e["ok"], "Dry run": e["dry_run"]} for e in reversed(lines)],
            hide_index=True,
        )
    else:
        st.write("No actions yet.")

# ---------- assistant ----------
st.header("💬 Ask GuberoAI")
st.caption("Not sure what something means? Ask. The assistant only explains: it cannot change "
           "anything. Use the buttons on the cards to approve or decline changes.")
render_chat(host_context(findings, results, applied, before, now, dry),
            key="host", suggestions=HOST_SUGGESTIONS)
persist_session_state()
render_footer()