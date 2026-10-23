from collections import OrderedDict
from copy import deepcopy
import re
from threading import RLock
from uuid import uuid4

import streamlit as st

PERSISTED_KEYS = (
    "findings",
    "results",
    "before",
    "applied",
    "declined",
    "dry_run",
    "net_devices",
    "net_results",
    "net_scanned",
    "chat_host",
    "chat_host_language",
    "chat_network",
    "chat_network_language",
)
SESSION_ID_KEY = "_persistent_session_id"
MAX_STORED_SESSIONS = 128


class _SessionStore:
    def __init__(self):
        self.records = OrderedDict()
        self.lock = RLock()


@st.cache_resource
def _session_store():
    return _SessionStore()


def restore_session_state():
    """Restore saved page data using the browser's stable URL session token."""
    query_id = st.query_params.get("session_id", "")
    session_id = (
        query_id
        if isinstance(query_id, str) and re.fullmatch(r"[0-9a-f]{32}", query_id)
        else ""
    )
    if not session_id:
        session_id = st.session_state.get(SESSION_ID_KEY)
    if not isinstance(session_id, str) or not re.fullmatch(r"[0-9a-f]{32}", session_id):
        session_id = uuid4().hex

    st.session_state[SESSION_ID_KEY] = session_id
    if query_id != session_id:
        st.query_params["session_id"] = session_id

    store = _session_store()
    with store.lock:
        saved = deepcopy(store.records.get(session_id, {}))
        if session_id in store.records:
            store.records.move_to_end(session_id)
    for key, value in saved.items():
        if key not in st.session_state:
            st.session_state[key] = value
    return session_id


def persist_session_state():
    """Keep scan details and decisions available after a browser refresh."""
    session_id = st.session_state.get(SESSION_ID_KEY)
    if not isinstance(session_id, str) or not re.fullmatch(r"[0-9a-f]{32}", session_id):
        return

    values = {
        key: deepcopy(st.session_state[key])
        for key in PERSISTED_KEYS
        if key in st.session_state
    }
    store = _session_store()
    with store.lock:
        store.records[session_id] = values
        store.records.move_to_end(session_id)
        while len(store.records) > MAX_STORED_SESSIONS:
            store.records.popitem(last=False)


def clear_all_reports():
    """Clear both scan reports and their chat histories for this browser session."""
    report_defaults = {
        "findings": None,
        "results": {},
        "before": None,
        "applied": {},
        "declined": set(),
        "net_devices": None,
        "net_results": {},
        "net_scanned": "",
        "chat_host": [],
        "chat_network": [],
    }
    for key, value in report_defaults.items():
        st.session_state[key] = value
    for key in list(st.session_state):
        if isinstance(key, str) and key.startswith("sure"):
            del st.session_state[key]
    persist_session_state()
