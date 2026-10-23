import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import streamlit as st
from groq import Groq
from network_assess import assess_devices, fallback_assessment
from network_scan import PROBE_PORTS, local_networks, scan_network

from network_assess import assess_devices, fallback_assessment
from network_scan import PROBE_PORTS, local_networks, scan_network

st.set_page_config(page_title="GuberoAI | Network Devices", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
    [data-testid="stAppViewContainer"] {
        background: #064643;
    }
    [data-testid="stHeader"] { background: rgba(3, 47, 45, 0.72); }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #064643 0%, #033633 100%);
        border-right: 1px solid rgba(167, 243, 208, 0.2);
    }
    [data-testid="stSidebarNav"] { display: none; }
    div.block-container { max-width: 1180px; padding-top: 2rem; padding-bottom: 3rem; }
    .gubero-hero {
        padding: 1.5rem 1.7rem;
        margin-bottom: 1.25rem;
        border: 1px solid rgba(167, 243, 208, 0.28);
        border-radius: 20px;
        background: linear-gradient(115deg, rgba(11, 92, 85, 0.96), rgba(3, 54, 51, 0.96));
    }
    .gubero-kicker {
        margin: 0 0 0.4rem;
        color: #a7f3d0;
        font-size: 0.76rem;
        font-weight: 700;
        letter-spacing: 0.15em;
        text-transform: uppercase;
    }
    .gubero-hero p { margin: 0; color: #ecfdf5; font-size: 1rem; }
    [data-testid="stMetric"] {
        padding: 1rem;
        border: 1px solid rgba(167, 243, 208, 0.22);
        border-radius: 16px;
        background: rgba(3, 54, 51, 0.72);
    }
    button[kind="primary"] {
        border: 1px solid #fcd34d;
        background: linear-gradient(100deg, #fbbf24, #f59e0b);
        color: #12312d;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="gubero-hero"><div class="gubero-kicker">GuberoAI · Network visibility</div>'
    "<p>Review devices and exposed services on a network you own or are authorized to test.</p></div>",
    unsafe_allow_html=True,
)
st.sidebar.markdown("### 🛡️ GuberoAI")
st.sidebar.caption("Security workspace")
st.sidebar.page_link("app.py", label="App", icon="🏠")
st.sidebar.page_link("pages/2_network_devices.py", label="Network Devices", icon="🌐")
st.sidebar.divider()
st.title("🌐 Network Devices")
st.caption(
    "Looks for risky services on other devices (cameras, routers, printers...) and "
    "tells you how to fix them. It never changes another device."
)

st.warning(
    "Only scan a network you own (your home Wi-Fi or your phone's hotspot) or have "
    "permission to test. Do NOT use this on hostel, college, office or public Wi-Fi: "
    "scanning other people's devices there is not allowed."
)

nets = local_networks()
if not nets:
    st.error("No private network found. Connect to your home Wi-Fi or hotspot first.")
    st.markdown(
        '<div style="text-align:center; padding:2rem 0 0.5rem; color:#94a3b8;">'
        '<a href="https://github.com/Acharya-Codes/agentic_ai_hackathon" '
        'target="_blank" rel="noopener noreferrer" style="color:#fcd34d; text-decoration:none;">'
        '↗ View GuberoAI on GitHub</a></div>',
        unsafe_allow_html=True,
    )
    st.stop()

with st.container(border=True):
    st.subheader("Scan setup")
    labels = [f"{name}: your address {ip}, scanning {net}" for name, ip, net in nets]
    pick = st.selectbox("Network to scan", range(len(nets)), format_func=lambda i: labels[i])
    _, my_ip, net = nets[pick]
    metric_network, metric_ports = st.columns(2)
    metric_network.metric("Network range", str(net))
    metric_ports.metric("Ports checked per device", len(PROBE_PORTS))
    st.caption("The scan only checks whether a connection is accepted on these common ports.")
    owns = st.checkbox("I own this network, or I have permission to test every device on it.")
    typed = st.text_input(f"To confirm, type the network range exactly as shown ({net}):")

ready = owns and typed.strip() == str(net)
if owns and typed and not ready:
    st.caption("⚠️ Confirmation range does not match exactly.")

key_ok = "GROQ_API_KEY" in os.environ
if not key_ok:
    st.info("GROQ_API_KEY is not set in this terminal, so basic rule-based advice will be used.")

if st.button("🔍 Scan network", type="primary", disabled=not ready):
    bar = st.progress(0.0, text="Looking for risky services...")
    devices = scan_network(net, my_ip, lambda x: bar.progress(x, text="Looking for risky services..."))
    bar.empty()
    
    results = {}
    if devices:
        if key_ok:
            with st.spinner("Asking the AI to explain what was found..."):
                try:
                    client = Groq(api_key=os.environ["GROQ_API_KEY"], max_retries=0)
                    results = assess_devices(client, devices)
                except Exception as e:
                    st.warning(f"AI assessment encountered an issue ({e}). Using rule-based guidance.")
                    results = {d["id"]: fallback_assessment(d) for d in devices}
        else:
            results = {d["id"]: fallback_assessment(d) for d in devices}

    st.session_state.net_devices = devices
    st.session_state.net_results = results
    st.session_state.net_scanned = str(net)

# Display results if present in session state
devices = st.session_state.get("net_devices")
if devices is None:
    st.markdown(
        '<div style="text-align:center; padding:2rem 0 0.5rem; color:#94a3b8;">'
        '<a href="https://github.com/Acharya-Codes/agentic_ai_hackathon" '
        'target="_blank" rel="noopener noreferrer" style="color:#fcd34d; text-decoration:none;">'
        '↗ View GuberoAI on GitHub</a></div>',
        unsafe_allow_html=True,
    )
    st.stop()

results = st.session_state.get("net_results", {})
st.subheader(f"Results for {st.session_state.get('net_scanned', net)}")

if not devices:
    st.success("No device on this network accepted a connection on the risky ports checked.")
    st.markdown(
        '<div style="text-align:center; padding:2rem 0 0.5rem; color:#94a3b8;">'
        '<a href="https://github.com/Acharya-Codes/agentic_ai_hackathon" '
        'target="_blank" rel="noopener noreferrer" style="color:#fcd34d; text-decoration:none;">'
        '↗ View GuberoAI on GitHub</a></div>',
        unsafe_allow_html=True,
    )
    st.stop()

# Safe sorting in case AI returns non-standard risk levels
order = {"high": 0, "medium": 1, "low": 2}
devices = sorted(
    devices, 
    key=lambda d: order.get(results.get(d["id"], {}).get("risk", "low").lower(), 3)
)

st.write(f"**{len(devices)}** device(s) with open risky ports.")
badge = {"high": "🔴 HIGH", "medium": "🟠 MEDIUM", "low": "🟢 LOW"}

for d in devices:
    a = results.get(d["id"], {})
    risk = a.get("risk", "low").lower()
    dev_type = a.get("device_type", "Unknown Device")
    
    title = f"{badge.get(risk, '🟢 LOW')}  ·  {d['ip']}  ·  {dev_type}"
    if d.get("is_this_pc"):
        title += "  (this PC)"

    with st.container(border=True):
        st.subheader(title)
        if d.get("hostname"):
            st.caption(f"Hostname: {d['hostname']}")
        
        st.write(f"**Why it matters:** {a.get('why', 'No explanation provided.')}")
        
        if d.get("open_ports"):
            st.dataframe(
                [{"Port": p["port"], "Greeting": p.get("banner", ""), "Known as": p.get("hint", "")}
                 for p in d["open_ports"]],
                hide_index=True,
            )
            
        st.write("**How to fix it (you do this on the device or your router):**")
        fix_steps = a.get("fix_steps", ["No specific fix steps available."])
        for i, step in enumerate(fix_steps, 1):
            st.write(f"{i}. {step}")
            
        st.caption(
            "Guidance written by AI" if a.get("source") != "rule" 
            else "Basic rule-based guidance (AI unavailable)"
        )

st.markdown(
    '<div style="text-align:center; padding:2rem 0 0.5rem; color:#94a3b8;">'
    '<a href="https://github.com/Acharya-Codes/agentic_ai_hackathon" '
    'target="_blank" rel="noopener noreferrer" style="color:#fcd34d; text-decoration:none;">'
    '↗ View GuberoAI on GitHub</a></div>',
    unsafe_allow_html=True,
)