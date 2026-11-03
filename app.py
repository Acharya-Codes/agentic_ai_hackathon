"""GuberoAI dashboard.

Run from an ADMINISTRATOR terminal (so firewall changes work):
    python -m streamlit run app.py

Needs: port_lister.py, port_knowledge.py, reasoner.py, actions.py, score.py,
chatbot.py, theme.py (+ .streamlit/config.toml and assets/) in the same folder,
and GROQ_API_KEY set in that terminal.
"""
import json
import os

import streamlit as st
from groq import Groq

import actions
import auth
import theme
from chatbot import HOST_SUGGESTIONS, host_context, render_chat
from port_knowledge import guide_for, hint_for
from port_lister import list_listening_ports
from reasoner import assess_all
from score import compute_score, grade

ACTIONABLE = ("block_with_firewall", "stop_service")

st.set_page_config(page_title="GuberoAI", page_icon="🛡️", layout="wide")
theme.inject()
auth.require_login()   # nothing below runs until you are signed in

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
    client = Groq(api_key=os.environ["GROQ_API_KEY"], max_retries=0)
    results = assess_all(client, to_send)
    st.session_state.findings = findings
    st.session_state.results = results
    st.session_state.applied = {}
    st.session_state.declined = set()
    st.session_state.before = compute_score(findings, results, set())


# ---------- sidebar ----------
admin = actions.is_admin()
key_ok = "GROQ_API_KEY" in os.environ
with st.sidebar:
    st.markdown("#### Controls")
    dry = st.checkbox("Dry run (preview only)", value=not admin,
                      help="When on, approvals show what would happen and change nothing.")
    if st.button("Scan this PC", type="primary", disabled=not key_ok):
        with st.spinner("Scanning and asking the AI to assess each port..."):
            scan_and_assess()
    if not key_ok:
        st.markdown(theme.notice("GROQ_API_KEY is not set in this terminal.", "warn"),
                    unsafe_allow_html=True)
    if not admin and not dry:
        st.markdown(theme.notice("Real changes will fail without Administrator rights.", "warn"),
                    unsafe_allow_html=True)
    with st.expander("What GuberoAI will never do"):
        st.markdown(
            "- Change anything without your approval\n"
            "- Touch core Windows ports or processes\n"
            "- Scan a network you haven't confirmed you own\n"
            "- Log in to, guess passwords for, or attack other devices\n"
            "- Hide what it did: every action is logged, and blocks can be undone"
        )
    auth.logout_button()

# ---------- hero: headline on the left, live port radar on the right ----------
_f = st.session_state.findings or []
_mit = {p for p, info in st.session_state.applied.items() if info["real"]}
hero_left, hero_right = st.columns([1.35, 1])
with hero_left:
    st.markdown(
        theme.hero(
            "Know what's exposed. Fix it with your approval.",
            "GuberoAI scans this PC, explains each risk in plain language, and changes "
            "nothing without your say-so.",
            [("Administrator" if admin else "Not administrator", "ok" if admin else "warn"),
             ("Dry run" if dry else "Live changes", "warn" if dry else "ok")],
            accent="exposed",
        ),
        unsafe_allow_html=True,
    )
with hero_right:
    st.markdown(theme.radar_from_findings(_f, st.session_state.results, _mit),
                unsafe_allow_html=True)

if st.session_state.findings is None:
    st.markdown(theme.timeline(["current", "todo", "todo", "todo", "todo"]), unsafe_allow_html=True)
    st.markdown(
        theme.empty_state("Ready when you are", [
            "Press Scan this PC in the sidebar.",
            "GuberoAI lists every open port and asks the AI to judge the risky ones.",
            "Review each finding. Approve a fix, or decline it. You are always in control.",
        ]),
        unsafe_allow_html=True,
    )
    st.stop()

findings = st.session_state.findings
results = st.session_state.results
applied = st.session_state.applied

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
visible = [(f, a) for f, a in needs_action if f["port"] not in st.session_state.declined]
visible.sort(key=lambda fa: 0 if fa[1]["risk"] == "high" else 1)

# ---------- score and stats ----------
mitigated = {port for port, info in applied.items() if info["real"]}
now = compute_score(findings, results, mitigated)
before = st.session_state.before
n_net = sum(1 for f in findings if f["exposure"] == "NETWORK-REACHABLE")

if applied:
    states = ["done"] * 5
elif visible:
    states = ["done", "done", "current", "todo", "todo"]
else:
    states = ["done"] * 5
st.markdown(theme.timeline(states), unsafe_allow_html=True)

left, right = st.columns([1.15, 2])
with left:
    st.markdown(theme.ring(now, before, grade(now)), unsafe_allow_html=True)
with right:
    c1, c2, c3 = st.columns(3)
    c1.markdown(theme.stat("Ports scanned", len(findings), f"{n_net} reachable from the network"),
                unsafe_allow_html=True)
    c2.markdown(theme.stat("Need your decision", len(visible), "approve or decline each",
                           "warn" if visible else "ok"), unsafe_allow_html=True)
    c3.markdown(theme.stat("Fixed", len(mitigated), "blocked or stopped", "ok"),
                unsafe_allow_html=True)
if dry:
    st.markdown(theme.notice("Dry run is on: approvals only preview the change. "
                             "Untick it in the sidebar for real changes.", "warn"),
                unsafe_allow_html=True)


def still_listening(port, pid):
    return any(x["port"] == port and x["pid"] == pid for x in list_listening_ports())


def render_card(f, a):
    port, pid, name = f["port"], f["pid"], f["process"]
    done = applied.get(port)
    exposure = "Reachable from network" if f["exposure"] == "NETWORK-REACHABLE" else "Local only"
    hint = hint_for(port)
    with st.container(border=True, key=f"card-{a['risk']}-{f['id']}"):
        body = (theme.card_head(a["risk"], f"Port {port}", name, [(exposure, "info")])
                + theme.kv("What it is", a["what_it_is"])
                + theme.kv("Why it matters", a["why"]))
        if hint:
            body += theme.note(f"Knowledge base: {hint}")
        st.markdown(body, unsafe_allow_html=True)

        if done:
            st.markdown(theme.notice(done["message"], "ok"), unsafe_allow_html=True)
            if done["kind"] == "block" and done["real"]:
                if st.button("Undo this change", key=f"undo{f['id']}"):
                    ok, msg = actions.unblock_port(port)
                    if ok:
                        applied.pop(port, None)
                        st.rerun()
                    st.error(msg)
            return

        if a["action"] == "block_with_firewall":
            st.markdown(theme.kv("Proposed fix", "Block inbound connections to this port (reversible)"),
                        unsafe_allow_html=True)
            st.code(" ".join(actions.block_command(port)), language="bash")
            col1, col2, _ = st.columns([1, 1, 2])
            if col1.button("Approve block", key=f"ok{f['id']}", type="primary"):
                ok, msg = actions.block_port(port, dry)
                if ok:
                    if dry:
                        text = "Dry run: this change was previewed only. Nothing was changed."
                    else:
                        text = ("Blocked. Firewall rule present: "
                                f"{actions.rule_exists(port)}. Other devices can no longer "
                                "reach this port.")
                    applied[port] = {"kind": "block", "real": not dry, "message": text}
                    st.rerun()
                st.error(f"Failed: {msg}")
            if col2.button("Decline", key=f"no{f['id']}"):
                actions.log_action("declined_block", {"port": port}, True, dry)
                st.session_state.declined.add(port)
                st.rerun()

        elif a["action"] == "stop_service":
            st.markdown(theme.kv("Proposed fix", f"Stop the process {name} (PID {pid})")
                        + theme.notice("This cannot be undone by the agent.", "warn"),
                        unsafe_allow_html=True)
            sure = st.checkbox("I understand this cannot be undone", key=f"sure{f['id']}")
            col1, col2, _ = st.columns([1, 1, 2])
            if col1.button("Approve stop", key=f"ok{f['id']}", type="primary", disabled=not sure):
                ok, msg = actions.stop_process(pid, name, dry)
                if ok:
                    if dry:
                        text = "Dry run: nothing was changed."
                    else:
                        text = f"Stopped {name}. Still listening: {still_listening(port, pid)}."
                    applied[port] = {"kind": "stop", "real": not dry, "message": text}
                    st.rerun()
                st.error(f"Failed: {msg}")
            if col2.button("Decline", key=f"no{f['id']}"):
                actions.log_action("declined_stop", {"pid": pid, "name": name}, True, dry)
                st.session_state.declined.add(port)
                st.rerun()


# ---------- findings that need a decision ----------
st.markdown(theme.section("Needs your decision", len(visible)), unsafe_allow_html=True)
if not visible:
    st.markdown(theme.notice("Nothing else needs action.", "ok"), unsafe_allow_html=True)
for f, a in visible:
    render_card(f, a)

# ---------- protected items: guided steps only ----------
if protected:
    st.markdown(theme.section("Flagged, but GuberoAI will not change these", len(protected)),
                unsafe_allow_html=True)
    for f, a, reason in protected:
        with st.container(border=True, key=f"card-protected-{f['id']}"):
            body = (theme.card_head(a["risk"], f"Port {f['port']}", f["process"])
                    + theme.kv("What it is", a["what_it_is"])
                    + theme.kv("Why it matters", a["why"])
                    + theme.notice(f"Safety rule: {reason}, so GuberoAI leaves it alone.", "info"))
            guide = guide_for(f["port"])
            if guide:
                body += theme.kv("Suggested fix (you do this yourself)", guide)
            st.markdown(body, unsafe_allow_html=True)

# ---------- full table ----------
st.markdown(theme.section("Details"), unsafe_allow_html=True)
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
            "Fixed": "yes" if f["port"] in mitigated else "",
        })
    st.dataframe(rows, hide_index=True)

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
st.markdown(theme.section("Ask GuberoAI"), unsafe_allow_html=True)
st.caption("Not sure what something means? Ask. The assistant only explains: it cannot change "
           "anything. Use the buttons on the cards to approve or decline changes.")
render_chat(host_context(findings, results, applied, before, now, dry),
            key="host", suggestions=HOST_SUGGESTIONS)
