"""GuberoAI look and feel.

Everything visual lives here so the pages stay clean: the CSS, the port radar,
the score ring, the agent timeline and the severity cards. All text that comes
from the machine or from the AI is HTML-escaped before it is shown.
"""
import html
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))

CSS = """<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
:root{--bg:#0A0E14;--surface:#121823;--surface2:#1A2230;--border:#243044;--text:#E8ECF3;--muted:#8B98AD;--accent:#4F8CFF;--high:#F87171;--med:#FBBF24;--ok:#34D399;}
.stApp{background-color:var(--bg);background-image:radial-gradient(900px 520px at 10% -10%,rgba(79,140,255,.20),transparent 62%),radial-gradient(700px 420px at 100% 0%,rgba(248,113,113,.08),transparent 62%),linear-gradient(rgba(255,255,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px);background-size:auto,auto,38px 38px,38px 38px;background-attachment:fixed;}
[data-testid="stHeader"]{background:transparent;}
.block-container{max-width:1120px;padding-top:2.2rem;padding-bottom:6rem;}
[data-testid="stSidebar"]{background:rgba(18,24,35,.96);border-right:1px solid var(--border);}
html,body,.stApp,[data-testid="stMarkdownContainer"],.stButton button,input,textarea,label{font-family:'Inter','Segoe UI',system-ui,sans-serif !important;}
code,pre,[data-testid="stCode"],[data-testid="stCode"] *{font-family:'JetBrains Mono',Consolas,monospace !important;}
.stButton button,[data-testid="stFormSubmitButton"] button{border-radius:10px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-weight:500;padding:.45rem 1rem;transition:border-color .15s,background .15s,transform .15s,box-shadow .15s;}
.stButton button:hover,[data-testid="stFormSubmitButton"] button:hover{border-color:var(--accent);background:#1F2A3D;color:#fff;transform:translateY(-1px);}
.stButton button:disabled{opacity:.4;transform:none;}
.stButton button[kind="primary"],.stButton button[data-testid="stBaseButton-primary"],[data-testid="stFormSubmitButton"] button[kind="primary"],[data-testid="stFormSubmitButton"] button[data-testid="stBaseButton-primary"]{background:linear-gradient(180deg,#5B96FF,#3E7BF0);border-color:#5B96FF;color:#fff;box-shadow:0 8px 22px -8px rgba(79,140,255,.75);}
.stButton button[kind="primary"]:hover,.stButton button[data-testid="stBaseButton-primary"]:hover{filter:brightness(1.1);}
div[class*="st-key-card-"]{background:linear-gradient(180deg,#151D2B,#10161F);border:1px solid var(--border);border-radius:16px;padding:1.2rem 1.4rem;box-shadow:inset 4px 0 0 var(--muted),0 14px 34px -22px rgba(0,0,0,.9);transition:border-color .2s,transform .2s;}
div[class*="st-key-card-"]:hover{border-color:#34496A;transform:translateY(-1px);}
div[class*="st-key-card-"] [data-testid="stVerticalBlockBorderWrapper"]{border:none;}
div[class*="st-key-card-high-"]{box-shadow:inset 4px 0 0 var(--high),0 14px 34px -22px rgba(248,113,113,.45);}
div[class*="st-key-card-medium-"]{box-shadow:inset 4px 0 0 var(--med),0 14px 34px -22px rgba(251,191,36,.35);}
div[class*="st-key-card-low-"]{box-shadow:inset 4px 0 0 var(--ok),0 14px 34px -22px rgba(0,0,0,.9);}
div[class*="st-key-card-protected-"]{box-shadow:inset 4px 0 0 #64748B,0 14px 34px -22px rgba(0,0,0,.9);}
[data-testid="stCode"]{border:1px solid var(--border);border-radius:10px;}
[data-testid="stCode"] pre{background:#0C111A !important;}
[data-testid="stExpander"]{border:1px solid var(--border);border-radius:12px;background:var(--surface);}
[data-testid="stChatMessage"]{background:var(--surface);border:1px solid var(--border);border-radius:12px;}
[data-testid="stForm"]{background:linear-gradient(180deg,#151D2B,#10161F);border:1px solid var(--border);border-radius:16px;padding:1.3rem;}
.gb-hero{margin-bottom:1rem;padding-top:.6rem;}
.gb-title{font-size:2.45rem;font-weight:800;letter-spacing:-.035em;line-height:1.1;margin:0 0 .6rem 0;}
.gb-accent{color:var(--accent);text-shadow:0 0 28px rgba(79,140,255,.55);}
.gb-sub{color:var(--muted);font-size:1.02rem;max-width:34rem;line-height:1.55;}
.gb-pills{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:1rem;}
.gb-pill{display:inline-flex;align-items:center;gap:.4rem;padding:.2rem .65rem;border-radius:999px;border:1px solid var(--border);font-size:.76rem;font-weight:600;letter-spacing:.02em;color:var(--muted);background:var(--surface);}
.gb-pill .gb-dot{width:7px;height:7px;border-radius:50%;background:currentColor;}
.gb-pill.ok{color:var(--ok);border-color:#1E5C47;}
.gb-pill.warn,.gb-pill.medium{color:var(--med);border-color:#6B5516;}
.gb-pill.high{color:var(--high);border-color:#6E2D2D;}
.gb-pill.low{color:var(--ok);border-color:#1E5C47;}
.gb-pill.info{color:var(--accent);border-color:#264A8A;}
.gb-panel{background:linear-gradient(180deg,#151D2B,#10161F);border:1px solid var(--border);border-radius:18px;padding:1.2rem 1.4rem;box-shadow:0 18px 40px -26px rgba(0,0,0,.95);}
.gb-ringrow{display:flex;align-items:center;gap:1.3rem;}
.gb-ringbox{position:relative;width:150px;height:150px;flex:none;}
.gb-ring{width:150px;height:150px;}
.gb-track{fill:none;stroke:#1E2838;stroke-width:10;}
.gb-arc{fill:none;stroke-width:10;stroke-linecap:round;stroke-dasharray:326.7;filter:drop-shadow(0 0 7px currentColor);animation:gb-fill 1.4s cubic-bezier(.22,.8,.3,1) forwards;}
@keyframes gb-fill{from{stroke-dashoffset:326.7;}to{stroke-dashoffset:var(--target);}}
.gb-ringcenter{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.gb-num{font-size:2.6rem;font-weight:800;line-height:1;letter-spacing:-.04em;}
.gb-of{color:var(--muted);font-size:.78rem;margin-top:.15rem;}
.gb-ringtext .gb-label{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.07em;}
.gb-ringtext .gb-grade{font-size:1.5rem;font-weight:700;margin:.15rem 0 .5rem 0;}
.gb-stat{background:linear-gradient(180deg,#151D2B,#10161F);border:1px solid var(--border);border-top:2px solid var(--accent);border-radius:16px;padding:1.1rem 1.2rem;height:100%;min-height:122px;box-shadow:0 18px 40px -26px rgba(0,0,0,.95);}
.gb-stat.warn{border-top-color:var(--med);}
.gb-stat.ok{border-top-color:var(--ok);}
.gb-stat .gb-l{color:var(--muted);font-size:.74rem;text-transform:uppercase;letter-spacing:.07em;}
.gb-stat .gb-v{font-size:2.3rem;font-weight:800;letter-spacing:-.04em;margin:.25rem 0 .1rem 0;}
.gb-stat .gb-s{color:var(--muted);font-size:.8rem;}
.gb-timeline{display:flex;gap:.6rem;margin:1.2rem 0 1.3rem 0;}
.gb-step{flex:1;}
.gb-stepbar{height:4px;background:#1E2838;border-radius:4px;margin-bottom:.6rem;}
.gb-step.done .gb-stepbar{background:var(--ok);}
.gb-step.current .gb-stepbar{background:var(--accent);box-shadow:0 0 14px rgba(79,140,255,.8);animation:gb-pulse 1.8s ease-in-out infinite;}
@keyframes gb-pulse{50%{opacity:.45;}}
.gb-step .gb-name{font-weight:600;font-size:.88rem;}
.gb-step .gb-desc{color:var(--muted);font-size:.76rem;}
.gb-step.todo .gb-name{color:var(--muted);}
.gb-section{display:flex;align-items:center;gap:.7rem;margin:2.2rem 0 .9rem 0;}
.gb-section h2{font-size:1.2rem;font-weight:700;margin:0;padding:0;letter-spacing:-.01em;}
.gb-section h2::before{content:"";display:inline-block;width:4px;height:1.05em;border-radius:2px;background:var(--accent);box-shadow:0 0 12px var(--accent);margin-right:.65rem;vertical-align:-.14em;}
.gb-count{background:var(--surface2);border:1px solid var(--border);border-radius:999px;padding:.05rem .6rem;font-size:.78rem;color:var(--muted);}
.gb-cardhead{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap;margin-bottom:.55rem;}
.gb-port{font-family:'JetBrains Mono',Consolas,monospace;font-size:1.1rem;font-weight:600;}
.gb-proc{color:var(--muted);font-size:.92rem;}
.gb-kv{margin:.5rem 0;line-height:1.55;}
.gb-kv .gb-k{display:block;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;margin-bottom:.1rem;}
.gb-note{color:var(--muted);font-size:.82rem;margin:.4rem 0 .6rem 0;font-style:italic;}
.gb-notice{border:1px solid var(--border);border-radius:12px;padding:.7rem 1rem;margin:.6rem 0;font-size:.9rem;line-height:1.5;}
.gb-notice.ok{border-color:#1E5C47;background:rgba(52,211,153,.08);color:#B7F0DB;}
.gb-notice.warn{border-color:#6B5516;background:rgba(251,191,36,.08);color:#F6DE9B;}
.gb-notice.info{border-color:#264A8A;background:rgba(79,140,255,.09);color:#C3D6FF;}
.gb-steps{margin:.3rem 0 .2rem 1.1rem;padding:0;line-height:1.65;}
.gb-empty h3{margin:0 0 .5rem 0;font-size:1.3rem;letter-spacing:-.02em;}
.gb-empty ol{margin:.6rem 0 0 1.2rem;padding:0;line-height:1.9;color:var(--text);}
.gb-radarbox{background:radial-gradient(circle at 50% 50%,rgba(79,140,255,.13),transparent 68%),linear-gradient(180deg,#131B28,#0E141D);border:1px solid var(--border);border-radius:20px;padding:.9rem .9rem .7rem;box-shadow:0 22px 50px -28px rgba(79,140,255,.45);}
.gb-radar{width:100%;height:auto;display:block;}
.gb-rring{fill:none;stroke:#2A3B57;stroke-width:.7;}
.gb-rring.outer{stroke:#3A5280;stroke-width:1;}
.gb-rline{stroke:#1E2B40;stroke-width:.6;}
.gb-sweep{transform-origin:110px 110px;animation:gb-spin 5.5s linear infinite;}
@keyframes gb-spin{to{transform:rotate(360deg);}}
.gb-wedge{fill:rgba(79,140,255,.22);}
.gb-lead{stroke:rgba(130,178,255,.95);stroke-width:1.2;}
.gb-core{fill:var(--accent);}
.gb-blip.high{fill:var(--high);}
.gb-blip.medium{fill:var(--med);}
.gb-blip.low{fill:var(--ok);opacity:.75;}
.gb-blip.unknown{fill:#94A3B8;}
.gb-blip.fixed{fill:var(--ok);opacity:1;}
.gb-ping{fill:none;stroke-width:1;transform-box:fill-box;transform-origin:center;animation:gb-ping 2.2s ease-out infinite;}
.gb-ping.high{stroke:var(--high);}
.gb-ping.medium{stroke:var(--med);animation-duration:3s;}
@keyframes gb-ping{from{transform:scale(1);opacity:.9;}to{transform:scale(3.4);opacity:0;}}
.gb-legend{display:flex;gap:.9rem;justify-content:center;flex-wrap:wrap;font-size:.72rem;color:var(--muted);margin-top:.35rem;}
.gb-legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:.35rem;}
.gb-legend2{text-align:center;font-size:.7rem;color:#5F6F89;margin-top:.15rem;}
.gb-brand{display:inline-flex;align-items:center;gap:.6rem;font-weight:800;font-size:1.6rem;letter-spacing:-.03em;}
.gb-brand b{color:var(--accent);}
.gb-login{text-align:center;margin:1.2rem 0 1rem 0;}
.gb-login .gb-title{font-size:2rem;margin-top:.9rem;}
.gb-login .gb-sub{margin:0 auto;}
</style>"""

SHIELD = ('<svg width="30" height="30" viewBox="0 0 32 32" fill="none">'
          '<path d="M16 3l11 4v8c0 7-4.6 12.3-11 14C9.6 27.3 5 22 5 15V7l11-4z" '
          'fill="rgba(79,140,255,0.16)" stroke="#4F8CFF" stroke-width="2" stroke-linejoin="round"/>'
          '<circle cx="16" cy="15" r="3.2" fill="#4F8CFF"/>'
          '<path d="M16 15v6M16 15l5-3M16 15l-5-3" stroke="#4F8CFF" stroke-width="1.6" '
          'stroke-linecap="round"/></svg>')


def esc(value):
    return html.escape(str(value), quote=True)


def inject():
    """Apply the theme and the sidebar logo. Call right after st.set_page_config."""
    import streamlit as st
    st.markdown(CSS, unsafe_allow_html=True)
    try:
        st.logo(os.path.join(HERE, "assets", "guberoai_logo.svg"), size="large")
    except Exception:
        pass   # older Streamlit versions have no st.logo


def brand():
    return f'<span class="gb-brand">{SHIELD}<span>Gubero<b>AI</b></span></span>'


def pill(text, kind=""):
    return f'<span class="gb-pill {esc(kind)}"><span class="gb-dot"></span>{esc(text)}</span>'


def hero(title, subtitle, pills=(), accent=""):
    safe = esc(title)
    if accent and esc(accent) in safe:
        safe = safe.replace(esc(accent), f'<span class="gb-accent">{esc(accent)}</span>', 1)
    row = "".join(pill(t, k) for t, k in pills)
    return (f'<div class="gb-hero"><h1 class="gb-title">{safe}</h1>'
            f'<div class="gb-sub">{esc(subtitle)}</div><div class="gb-pills">{row}</div></div>')


def login_header(title):
    return (f'<div class="gb-login">{brand()}{radar([], width=250)}'
            f'<h1 class="gb-title">{esc(title)}</h1>'
            '<div class="gb-sub">Sign in to open your dashboard.</div></div>')


def ring(score, before, label):
    circ = 326.7
    offset = round(circ * (1 - max(0, min(100, score)) / 100), 1)
    color = "var(--ok)" if score >= 90 else "var(--med)" if score >= 70 else "var(--high)"
    delta = ""
    if before is not None and score != before:
        diff = score - before
        delta = pill(f"{diff:+d} since scan", "ok" if diff > 0 else "warn")
    return (
        '<div class="gb-panel"><div class="gb-ringrow"><div class="gb-ringbox">'
        '<svg class="gb-ring" viewBox="0 0 120 120">'
        '<circle class="gb-track" cx="60" cy="60" r="52"/>'
        f'<circle class="gb-arc" cx="60" cy="60" r="52" transform="rotate(-90 60 60)" '
        f'style="stroke:{color};color:{color};--target:{offset}"/></svg>'
        f'<div class="gb-ringcenter"><div class="gb-num">{int(score)}</div>'
        '<div class="gb-of">out of 100</div></div></div>'
        f'<div class="gb-ringtext"><div class="gb-label">Security score</div>'
        f'<div class="gb-grade">{esc(label)}</div>{delta}</div></div></div>'
    )


def stat(label, value, sub="", kind=""):
    return (f'<div class="gb-stat {esc(kind)}"><div class="gb-l">{esc(label)}</div>'
            f'<div class="gb-v">{esc(value)}</div><div class="gb-s">{esc(sub)}</div></div>')


# ---------- the port radar ----------
def radar(blips, width=None):
    """A radar picture of what was found. Each blip is a dict with:
    seed (number that picks its angle), ring ('outer' = reachable from the network,
    'inner' = local only), risk ('high'/'medium'/'low'/'unknown') and fixed (bool)."""
    cx = cy = 110
    parts = []
    for r, cls in ((100, "outer"), (75, ""), (50, ""), (25, "")):
        parts.append(f'<circle class="gb-rring {cls}" cx="{cx}" cy="{cy}" r="{r}"/>')
    parts.append(f'<line class="gb-rline" x1="10" y1="{cy}" x2="210" y2="{cy}"/>')
    parts.append(f'<line class="gb-rline" x1="{cx}" y1="10" x2="{cx}" y2="210"/>')
    parts.append('<g class="gb-sweep"><path class="gb-wedge" d="M110 110 L210 110 '
                 'A100 100 0 0 0 174.3 33.4 Z"/>'
                 '<line class="gb-lead" x1="110" y1="110" x2="210" y2="110"/></g>')
    for i, b in enumerate(blips):
        angle = math.radians((float(b["seed"]) * 137.508) % 360)
        radius = (78 + (i % 3) * 7) if b["ring"] == "outer" else (28 + (i % 4) * 8)
        x = round(cx + radius * math.cos(angle), 1)
        y = round(cy + radius * math.sin(angle), 1)
        risk = b["risk"] if b["risk"] in ("high", "medium", "low") else "unknown"
        state = "fixed" if b.get("fixed") else risk
        size = 4.2 if risk in ("high", "medium") and not b.get("fixed") else 3.2
        if state in ("high", "medium"):
            parts.append(f'<circle class="gb-ping {state}" cx="{x}" cy="{y}" r="{size}"/>')
        parts.append(f'<circle class="gb-blip {state}" cx="{x}" cy="{y}" r="{size}"/>')
    parts.append(f'<circle class="gb-core" cx="{cx}" cy="{cy}" r="3.4"/>')
    legend = ('<div class="gb-legend">'
              '<span><i style="background:var(--high)"></i>High</span>'
              '<span><i style="background:var(--med)"></i>Medium</span>'
              '<span><i style="background:var(--ok);opacity:.75"></i>Low</span>'
              '<span><i style="background:var(--ok)"></i>Fixed</span></div>'
              '<div class="gb-legend2">Outer ring: reachable from the network. Inner: local only.</div>')
    style = f' style="max-width:{int(width)}px;margin:1rem auto 0;"' if width else ""
    return (f'<div class="gb-radarbox"{style}><svg class="gb-radar" viewBox="0 0 220 220" '
            f'role="img" aria-label="Radar of scanned ports">{"".join(parts)}</svg>{legend}</div>')


def radar_from_findings(findings, results, mitigated):
    blips = []
    for f in findings:
        a = results.get(f["id"])
        blips.append({
            "seed": f["port"],
            "ring": "outer" if f["exposure"] == "NETWORK-REACHABLE" else "inner",
            "risk": a["risk"] if a else "unknown",
            "fixed": f["port"] in mitigated,
        })
    return radar(blips)


def radar_from_devices(devices, results):
    blips = []
    for d in devices or []:
        a = results.get(d["id"])
        try:
            seed = int(str(d["ip"]).rsplit(".", 1)[-1])
        except ValueError:
            seed = d["id"]
        blips.append({"seed": seed, "ring": "outer",
                      "risk": a["risk"] if a else "unknown", "fixed": False})
    return radar(blips)


STEPS = [("Sense", "Scan open ports"), ("Reason", "AI judges the risk"),
         ("Ask", "You decide"), ("Act", "Fix is applied"), ("Verify", "Checked and logged")]


def timeline(states):
    parts = []
    for (name, desc), state in zip(STEPS, states):
        parts.append(f'<div class="gb-step {esc(state)}"><div class="gb-stepbar"></div>'
                     f'<div class="gb-name">{esc(name)}</div><div class="gb-desc">{esc(desc)}</div></div>')
    return '<div class="gb-timeline">' + "".join(parts) + "</div>"


def section(title, count=None):
    chip = f'<span class="gb-count">{esc(count)}</span>' if count is not None else ""
    return f'<div class="gb-section"><h2>{esc(title)}</h2>{chip}</div>'


def card_head(risk, title, subtitle="", tags=()):
    label = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(risk, risk.upper())
    extra = "".join(pill(t, k) for t, k in tags)
    sub = f'<span class="gb-proc">{esc(subtitle)}</span>' if subtitle else ""
    return (f'<div class="gb-cardhead">{pill(label, risk)}<span class="gb-port">{esc(title)}</span>'
            f'{sub}{extra}</div>')


def kv(label, text):
    return f'<div class="gb-kv"><span class="gb-k">{esc(label)}</span>{esc(text)}</div>'


def note(text):
    return f'<div class="gb-note">{esc(text)}</div>'


def notice(text, kind="info"):
    return f'<div class="gb-notice {esc(kind)}">{esc(text)}</div>'


def steps_list(steps):
    return '<ol class="gb-steps">' + "".join(f"<li>{esc(s)}</li>" for s in steps) + "</ol>"


def empty_state(title, lines):
    items = "".join(f"<li>{esc(x)}</li>" for x in lines)
    return f'<div class="gb-panel gb-empty"><h3>{esc(title)}</h3><ol>{items}</ol></div>'
