"""Streamlit entrypoint.

    streamlit run app.py

Every answer ships with the records it was built from. An operator should be able
to check the assistant's work without leaving the chat — a summary nobody can
verify is worse than no summary.
"""

from __future__ import annotations

import os

import streamlit as st
from dotenv import load_dotenv

from chatbot.controller import ConfigurationError

load_dotenv()

st.set_page_config(page_title="Security Assistant", page_icon="🛡️", layout="centered")

st.title("Security Monitoring Assistant")
st.caption("Read-only access to alarms, events, logs, and device status.")

with st.sidebar:
    st.subheader("Status")
    mode = os.getenv("SECURITY_CLIENT", "mock")
    st.write(f"**Data source:** `{mode}`")
    if mode == "mock":
        st.caption("Synthetic fixtures. No real security platform is being contacted.")
    st.write(
        "**Claude credentials:** "
        + ("configured" if os.getenv("ANTHROPIC_API_KEY") else "not found")
    )
    st.divider()
    st.caption(
        "This assistant is read-only. It cannot acknowledge alarms, change device "
        "configuration, restart systems, or delete logs."
    )


@st.cache_resource(show_spinner=False)
def get_controller():
    from chatbot.controller import Controller

    return Controller()


if "history" not in st.session_state:
    st.session_state.history = []   # Claude message history (tool blocks and all)
if "transcript" not in st.session_state:
    st.session_state.transcript = []  # what the user sees


def render_evidence(evidence) -> None:
    if not evidence:
        return
    for outcome in evidence:
        payload = outcome.payload
        if outcome.is_error:
            label = f"⚠️ {outcome.action} — rejected"
        else:
            shown, total = payload.get("returned", 0), payload.get("total_matched", 0)
            suffix = f"{shown} of {total}" if payload.get("truncated") else str(shown)
            label = f"Retrieved records · {outcome.action} ({suffix})"
        with st.expander(label):
            st.caption(f"Parameters: `{outcome.parameters}`")
            st.json(payload)


for entry in st.session_state.transcript:
    with st.chat_message(entry["role"]):
        st.markdown(entry["content"])
        render_evidence(entry.get("evidence", []))

question = st.chat_input("Ask about alarms, events, logs, or devices")

if question:
    st.session_state.transcript.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        try:
            with st.spinner("Querying the security platform…"):
                controller = get_controller()
                turn, history = controller.process_message(
                    question, st.session_state.history
                )
            st.session_state.history = history

            st.markdown(turn.answer)
            render_evidence(turn.evidence)
            st.session_state.transcript.append(
                {"role": "assistant", "content": turn.answer, "evidence": turn.evidence}
            )
        except (ConfigurationError, FileNotFoundError) as exc:
            # A setup problem, not an outage. Saying "could not retrieve" here would
            # send someone investigating a security platform that is perfectly fine.
            message = f"**Setup incomplete.** {exc}"
            st.warning(message)
            st.session_state.transcript.append(
                {"role": "assistant", "content": message}
            )
        except Exception:
            # Generic on the surface, detailed in the log. Tokens, stack traces,
            # internal URLs, and raw server errors never reach the chat.
            st.error(
                "I could not retrieve the security information. Please try again, or "
                "contact the system administrator if this continues."
            )
            st.session_state.transcript.append(
                {
                    "role": "assistant",
                    "content": "_Retrieval failed — see the administrator._",
                }
            )
