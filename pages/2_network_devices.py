"""Network devices page. Appears in the sidebar automatically next to the main page
because it lives in the 'pages' folder beside app.py."""
import os

import streamlit as st
from groq import Groq

import theme
from chatbot import NETWORK_SUGGESTIONS, network_context, render_chat
from network_assess import assess_devices, fallback_assessment
from network_scan import PROBE_PORTS, local_networks, scan_network

st.set_page_config(page_title="GuberoAI: Network devices", page_icon="🛡️", layout="wide")
theme.inject()

st.markdown(
    theme.hero(
        "Check the devices around you.",
        "GuberoAI looks for risky services on other devices (cameras, routers, printers) "
        "and tells you how to fix them. It never changes another device.",
        [("Read-only", "ok"), ("Your network only", "info")],
    ),
    unsafe_allow_html=True,
)
st.markdown(
    theme.notice("Only scan a network you own (your home Wi-Fi or your phone's hotspot) or have "
                 "permission to test. Do NOT use this on hostel, college, office or public Wi-Fi: "
                 "scanning other people's devices there is not allowed.", "warn"),
    unsafe_allow_html=True,
)

nets = local_networks()
if not nets:
    st.error("No private network found. Connect to your home Wi-Fi or hotspot first.")
    st.stop()

labels = [f"{name}: your address {ip}, scanning {net}" for name, ip, net in nets]
pick = st.selectbox("Network to scan", range(len(nets)), format_func=lambda i: labels[i])
_, my_ip, net = nets[pick]

st.write(f"The scan tries {len(PROBE_PORTS)} common risky ports on each address in "
         f"**{net}**. It only checks whether a port accepts a connection.")
owns = st.checkbox("I own this network, or I have permission to test every device on it.")
typed = st.text_input(f"To confirm, type the network range exactly as shown ({net}):")
ready = owns and typed.strip() == str(net)
key_ok = "GROQ_API_KEY" in os.environ
if not key_ok:
    st.markdown(theme.notice("GROQ_API_KEY is not set in this terminal, so basic rule-based "
                             "advice will be used.", "info"), unsafe_allow_html=True)

if st.button("Scan network", type="primary", disabled=not ready):
    bar = st.progress(0.0, text="Looking for risky services...")
    devices = scan_network(net, my_ip,
                           lambda x: bar.progress(x, text="Looking for risky services..."))
    bar.empty()
    results = {}
    if devices:
        if key_ok:
            with st.spinner("Asking the AI to explain what was found..."):
                client = Groq(api_key=os.environ["GROQ_API_KEY"], max_retries=0)
                results = assess_devices(client, devices)
        else:
            results = {d["id"]: fallback_assessment(d) for d in devices}
    st.session_state.net_devices = devices
    st.session_state.net_results = results
    st.session_state.net_scanned = str(net)

devices = st.session_state.get("net_devices")
if devices is None:
    st.stop()
results = st.session_state.net_results
st.markdown(theme.section(f"Results for {st.session_state.net_scanned}", len(devices)),
            unsafe_allow_html=True)
if not devices:
    st.markdown(theme.notice("No device on this network accepted a connection on the risky "
                             "ports checked.", "ok"), unsafe_allow_html=True)
    st.stop()

order = {"high": 0, "medium": 1, "low": 2}
devices = sorted(devices, key=lambda d: order[results[d["id"]]["risk"]])
for d in devices:
    a = results[d["id"]]
    tags = [("This PC", "info")] if d["is_this_pc"] else []
    with st.container(border=True, key=f"card-{a['risk']}-{d['id']}"):
        body = theme.card_head(a["risk"], d["ip"], a["device_type"], tags)
        if d["hostname"]:
            body += theme.note(f"Hostname: {d['hostname']}")
        body += theme.kv("Why it matters", a["why"])
        st.markdown(body, unsafe_allow_html=True)
        st.dataframe(
            [{"Port": p["port"], "Greeting": p["banner"], "Known as": p["hint"]}
             for p in d["open_ports"]],
            hide_index=True,
        )
        st.markdown(
            theme.kv("How to fix it (you do this on the device or your router)", "")
            + theme.steps_list(a["fix_steps"])
            + theme.note("Guidance written by AI" if a.get("source") != "rule"
                         else "Basic rule-based guidance (AI unavailable)"),
            unsafe_allow_html=True,
        )

st.markdown(theme.section("Ask GuberoAI"), unsafe_allow_html=True)
st.caption("The assistant only explains the results above. It cannot change any device.")
render_chat(network_context(devices, results, st.session_state.net_scanned),
            key="network", suggestions=NETWORK_SUGGESTIONS)
