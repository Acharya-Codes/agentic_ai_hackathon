"""Single-user login gate for GuberoAI.

The password is never stored. Only a salted PBKDF2 hash is saved in auth.json,
which you create yourself with:   python set_password.py

Protections: password hashing, constant-time comparison, a lockout after
repeated wrong attempts (survives page refresh), and sign-out after 30 minutes
of inactivity. Call require_login() near the top of EVERY page.

Honest limits: this keeps other people out of the dashboard. It does not
protect against someone who already has full access to your PC's files.
"""
import hashlib
import hmac
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AUTH_FILE = os.path.join(HERE, "auth.json")
ATTEMPTS_FILE = os.path.join(HERE, ".auth_attempts.json")

ITERATIONS = 600_000
MIN_PASSWORD = 10
MAX_FAILS = 5            # wrong attempts allowed...
LOCK_WINDOW = 300        # ...within this many seconds
IDLE_TIMEOUT = 30 * 60   # seconds of inactivity before signing out


# ---------- credentials ----------
def _hash(password, salt, iterations):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def save_credentials(username, password):
    salt = os.urandom(16)
    data = {
        "username": username,
        "salt": salt.hex(),
        "iterations": ITERATIONS,
        "hash": _hash(password, salt, ITERATIONS).hex(),
    }
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)
    clear_fails()


def _load():
    try:
        with open(AUTH_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def verify(username, password):
    cfg = _load()
    if not cfg:
        return False
    expected = bytes.fromhex(cfg["hash"])
    actual = _hash(password, bytes.fromhex(cfg["salt"]), int(cfg["iterations"]))
    user_ok = hmac.compare_digest(username.encode("utf-8"), cfg["username"].encode("utf-8"))
    pass_ok = hmac.compare_digest(actual, expected)
    return user_ok and pass_ok


# ---------- lockout ----------
def _recent_fails():
    try:
        with open(ATTEMPTS_FILE, encoding="utf-8") as f:
            stamps = json.load(f)
    except (OSError, ValueError):
        return []
    now = time.time()
    return [t for t in stamps if isinstance(t, (int, float)) and now - t < LOCK_WINDOW]


def record_fail():
    stamps = _recent_fails() + [time.time()]
    with open(ATTEMPTS_FILE, "w", encoding="utf-8") as f:
        json.dump(stamps, f)
    return len(stamps)


def clear_fails():
    try:
        os.remove(ATTEMPTS_FILE)
    except OSError:
        pass


def lock_remaining():
    """Seconds left on the lockout, or 0 if sign-in is allowed."""
    recent = _recent_fails()
    if len(recent) < MAX_FAILS:
        return 0
    return max(1, int(LOCK_WINDOW - (time.time() - recent[-MAX_FAILS])) + 1)


# ---------- Streamlit gate ----------
def require_login():
    import streamlit as st
    import theme

    if not os.path.exists(AUTH_FILE):
        _hide_sidebar(st)
        _, mid, _ = st.columns([1, 1.3, 1])
        with mid:
            st.markdown(theme.login_header("Set up your account"), unsafe_allow_html=True)
            st.markdown(theme.notice(
                "No account exists yet. In your terminal, run:  python set_password.py  "
                "then reload this page.", "info"), unsafe_allow_html=True)
        st.stop()

    now = time.time()
    if st.session_state.get("auth_ok"):
        if now - st.session_state.get("auth_last", now) > IDLE_TIMEOUT:
            st.session_state.clear()
            st.session_state["auth_msg"] = "You were signed out after 30 minutes of inactivity."
        else:
            st.session_state["auth_last"] = now
            return

    _hide_sidebar(st)
    _, mid, _ = st.columns([1, 1.3, 1])
    with mid:
        st.markdown(theme.login_header("Welcome back."), unsafe_allow_html=True)
        message = st.session_state.pop("auth_msg", None)
        if message:
            st.markdown(theme.notice(message, "info"), unsafe_allow_html=True)
        wait = lock_remaining()
        if wait:
            st.markdown(theme.notice(
                f"Too many wrong attempts. Try again in about {wait} seconds.", "warn"),
                unsafe_allow_html=True)
        else:
            with st.form("login", clear_on_submit=False):
                user = st.text_input("Username")
                pw = st.text_input("Password", type="password")
                go = st.form_submit_button("Sign in", type="primary")
            if go:
                if verify(user.strip(), pw):
                    clear_fails()
                    st.session_state["auth_ok"] = True
                    st.session_state["auth_last"] = time.time()
                    st.rerun()
                count = record_fail()
                left = MAX_FAILS - count
                extra = f" {left} attempt(s) left before a short lockout." if left > 0 else ""
                st.markdown(theme.notice("Incorrect username or password." + extra, "warn"),
                            unsafe_allow_html=True)
    st.stop()


def _hide_sidebar(st):
    st.markdown(
        "<style>[data-testid='stSidebar'],[data-testid='stSidebarCollapsedControl'],"
        "[data-testid='stSidebarNav']{display:none !important;}</style>",
        unsafe_allow_html=True,
    )


def logout_button():
    """Put a Sign out button in the sidebar."""
    import streamlit as st
    if st.button("Sign out", key="gb_signout"):
        st.session_state.clear()
        st.rerun()
