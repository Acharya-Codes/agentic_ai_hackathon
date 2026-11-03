"""GuberoAI look and feel.

Everything visual lives here so the pages stay clean: the CSS, the score ring,
the agent timeline, the severity cards. All text that comes from the machine or
from the AI is HTML-escaped before it is shown.
"""
import html
import os

HERE = os.path.dirname(os.path.abspath(__file__))

CSS = """<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
:root{--bg:#0A0E14;--surface:#121823;--surface2:#1A2230;--border:#243044;--text:#E8ECF3;--muted:#8B98AD;--accent:#4F8CFF;--high:#F87171;--med:#FBBF24;--ok:#34D399;}
.stApp{background:var(--bg);}
[data-testid="stHeader"]{background:transparent;}
.block-container{max-width:1120px;padding-top:2.2rem;padding-bottom:6rem;}
[data-testid="stSidebar"]{background:var(--surface);border-right:1px solid var(--border);}
html,body,.stApp,[data-testid="stMarkdownContainer"],.stButton button,input,textarea,label{font-family:'Inter','Segoe UI',system-ui,sans-serif !important;}
code,pre,[data-testid="stCode"],[data-testid="stCode"] *{font-family:'JetBrains Mono',Consolas,monospace !important;}
.stButton button{border-radius:10px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-weight:500;padding:.45rem 1rem;transition:border-color .15s,background .15s;}
.stButton button:hover{border-color:var(--accent);background:#1F2A3D;color:#fff;}
.stButton button:disabled{opacity:.4;}
.stButton button[kind="primary"],.stButton button[data-testid="stBaseButton-primary"]{background:var(--accent);border-color:var(--accent);color:#fff;}
.stButton button[kind="primary"]:hover,.stButton button[data-testid="stBaseButton-primary"]:hover{filter:brightness(1.12);}
div[class*="st-key-card-"]{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:1.1rem 1.3rem;box-shadow:inset 4px 0 0 var(--muted);}
div[class*="st-key-card-"] [data-testid="stVerticalBlockBorderWrapper"]{border:none;}
div[class*="st-key-card-high-"]{box-shadow:inset 4px 0 0 var(--high);}
div[class*="st-key-card-medium-"]{box-shadow:inset 4px 0 0 var(--med);}
div[class*="st-key-card-low-"]{box-shadow:inset 4px 0 0 var(--ok);}
div[class*="st-key-card-protected-"]{box-shadow:inset 4px 0 0 #64748B;}
[data-testid="stCode"]{border:1px solid var(--border);border-radius:10px;}
[data-testid="stCode"] pre{background:#0C111A !important;}
[data-testid="stExpander"]{border:1px solid var(--border);border-radius:12px;background:var(--surface);}
[data-testid="stChatMessage"]{background:var(--surface);border:1px solid var(--border);border-radius:12px;}
.gb-hero{margin-bottom:1.2rem;}
.gb-title{font-size:2.05rem;font-weight:700;letter-spacing:-.03em;line-height:1.15;margin:0 0 .4rem 0;}
.gb-sub{color:var(--muted);font-size:1rem;max-width:46rem;line-height:1.5;}
.gb-pills{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.9rem;}
.gb-pill{display:inline-flex;align-items:center;gap:.4rem;padding:.2rem .65rem;border-radius:999px;border:1px solid var(--border);font-size:.76rem;font-weight:600;letter-spacing:.02em;color:var(--muted);background:var(--surface);}
.gb-pill .gb-dot{width:7px;height:7px;border-radius:50%;background:currentColor;}
.gb-pill.ok{color:var(--ok);border-color:#1E5C47;}
.gb-pill.warn,.gb-pill.medium{color:var(--med);border-color:#6B5516;}
.gb-pill.high{color:var(--high);border-color:#6E2D2D;}
.gb-pill.low{color:var(--ok);border-color:#1E5C47;}
.gb-pill.info{color:var(--accent);border-color:#264A8A;}
.gb-panel{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1.2rem 1.4rem;}
.gb-ringrow{display:flex;align-items:center;gap:1.3rem;}
.gb-ringbox{position:relative;width:150px;height:150px;flex:none;}
.gb-ring{width:150px;height:150px;}
.gb-track{fill:none;stroke:#1E2838;stroke-width:10;}
.gb-arc{fill:none;stroke-width:10;stroke-linecap:round;stroke-dasharray:326.7;animation:gb-fill 1.3s cubic-bezier(.22,.8,.3,1) forwards;}
@keyframes gb-fill{from{stroke-dashoffset:326.7;}to{stroke-dashoffset:var(--target);}}
.gb-ringcenter{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.gb-num{font-size:2.5rem;font-weight:700;line-height:1;letter-spacing:-.03em;}
.gb-of{color:var(--muted);font-size:.78rem;margin-top:.15rem;}
.gb-ringtext .gb-label{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.07em;}
.gb-ringtext .gb-grade{font-size:1.45rem;font-weight:700;margin:.15rem 0 .5rem 0;}
.gb-stat{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:1.1rem 1.2rem;height:100%;min-height:122px;}
.gb-stat .gb-l{color:var(--muted);font-size:.74rem;text-transform:uppercase;letter-spacing:.07em;}
.gb-stat .gb-v{font-size:2.1rem;font-weight:700;letter-spacing:-.03em;margin:.25rem 0 .1rem 0;}
.gb-stat .gb-s{color:var(--muted);font-size:.8rem;}
.gb-timeline{display:flex;gap:.6rem;margin:1.5rem 0 .4rem 0;}
.gb-step{flex:1;}
.gb-stepbar{height:3px;background:#1E2838;border-radius:3px;margin-bottom:.6rem;}
.gb-step.done .gb-stepbar{background:var(--ok);}
.gb-step.current .gb-stepbar{background:var(--accent);box-shadow:0 0 12px rgba(79,140,255,.6);}
.gb-step .gb-name{font-weight:600;font-size:.88rem;}
.gb-step .gb-desc{color:var(--muted);font-size:.76rem;}
.gb-step.todo .gb-name{color:var(--muted);}
.gb-section{display:flex;align-items:center;gap:.7rem;margin:2.1rem 0 .85rem 0;}
.gb-section h2{font-size:1.15rem;font-weight:600;margin:0;padding:0;letter-spacing:-.01em;}
.gb-count{background:var(--surface2);border:1px solid var(--border);border-radius:999px;padding:.05rem .6rem;font-size:.78rem;color:var(--muted);}
.gb-cardhead{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap;margin-bottom:.55rem;}
.gb-port{font-family:'JetBrains Mono',Consolas,monospace;font-size:1.05rem;font-weight:600;}
.gb-proc{color:var(--muted);font-size:.92rem;}
.gb-kv{margin:.5rem 0;line-height:1.55;}
.gb-kv .gb-k{display:block;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;margin-bottom:.1rem;}
.gb-note{color:var(--muted);font-size:.82rem;margin:.4rem 0 .6rem 0;font-style:italic;}
.gb-notice{border:1px solid var(--border);border-radius:12px;padding:.7rem 1rem;margin:.6rem 0;font-size:.9rem;line-height:1.5;}
.gb-notice.ok{border-color:#1E5C47;background:rgba(52,211,153,.07);color:#B7F0DB;}
.gb-notice.warn{border-color:#6B5516;background:rgba(251,191,36,.07);color:#F6DE9B;}
.gb-notice.info{border-color:#264A8A;background:rgba(79,140,255,.08);color:#C3D6FF;}
.gb-steps{margin:.3rem 0 .2rem 1.1rem;padding:0;line-height:1.65;}
.gb-empty{text-align:left;}
.gb-empty h3{margin:0 0 .5rem 0;font-size:1.3rem;letter-spacing:-.02em;}
.gb-empty ol{margin:.6rem 0 0 1.2rem;padding:0;line-height:1.9;color:var(--text);}
</style>"""


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


def pill(text, kind=""):
    return f'<span class="gb-pill {esc(kind)}"><span class="gb-dot"></span>{esc(text)}</span>'


def hero(title, subtitle, pills=()):
    row = "".join(pill(t, k) for t, k in pills)
    return (f'<div class="gb-hero"><h1 class="gb-title">{esc(title)}</h1>'
            f'<div class="gb-sub">{esc(subtitle)}</div><div class="gb-pills">{row}</div></div>')


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
        f'style="stroke:{color};--target:{offset}"/></svg>'
        f'<div class="gb-ringcenter"><div class="gb-num">{int(score)}</div>'
        '<div class="gb-of">out of 100</div></div></div>'
        f'<div class="gb-ringtext"><div class="gb-label">Security score</div>'
        f'<div class="gb-grade">{esc(label)}</div>{delta}</div></div></div>'
    )


def stat(label, value, sub=""):
    return (f'<div class="gb-stat"><div class="gb-l">{esc(label)}</div>'
            f'<div class="gb-v">{esc(value)}</div><div class="gb-s">{esc(sub)}</div></div>')


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
