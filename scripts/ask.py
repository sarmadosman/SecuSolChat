#!/usr/bin/env python3
"""Drive the pipeline from the terminal — no Streamlit, no browser.

Faster than the UI for iterating on prompts and routing, and it prints the tool
calls, so you can see *why* an answer came out the way it did rather than
inferring it.

    python scripts/ask.py "Are there any critical alarms?"
    python scripts/ask.py                 # interactive, keeps conversation context
    python scripts/ask.py --demo          # replay the PLAN.md §11 demo script
    python scripts/ask.py --dry-run "..."  # no API call; show what would be sent
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

DEMO_SCRIPT = [
    "Are there any critical alarms?",
    "Which one is newest?",
    "Show the device status.",
    "Restart it.",
]


def show_turn(turn) -> None:
    for outcome in turn.evidence:
        payload = outcome.payload
        if outcome.is_error:
            print(f"  ⚠ {outcome.action} rejected: {payload.get('error')}")
            continue
        detail = f"{payload['returned']}"
        if payload["truncated"]:
            detail += f" of {payload['total_matched']}"
        params = {k: v for k, v in outcome.parameters.items() if v is not None}
        print(f"  → {outcome.action}({json.dumps(params)}) — {detail} record(s)")
    print()
    print(turn.answer)
    print()


def dry_run(question: str) -> None:
    """Everything except the model call — useful with no key, and it costs nothing."""
    from chatbot.prompts import SYSTEM_PROMPT
    from chatbot.schemas import tool_definitions

    print(f"question: {question}\n")
    print(f"system prompt: {len(SYSTEM_PROMPT)} chars")
    print("tools offered:")
    for definition in tool_definitions():
        params = ", ".join(sorted(definition["input_schema"]["properties"]))
        print(f"  - {definition['name']}({params})")
    print("\nNo request was sent. Set ANTHROPIC_API_KEY to run for real.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question", nargs="*", help="question to ask")
    parser.add_argument("--demo", action="store_true", help="replay the demo script")
    parser.add_argument("--dry-run", action="store_true", help="no API call")
    args = parser.parse_args()

    question = " ".join(args.question).strip()

    if args.dry_run:
        dry_run(question or "Are there any critical alarms?")
        return 0

    from chatbot.controller import ConfigurationError, Controller

    try:
        controller = Controller()
    except FileNotFoundError as exc:
        print(f"Setup incomplete: {exc}", file=sys.stderr)
        return 2

    history: list = []
    questions = DEMO_SCRIPT if args.demo else ([question] if question else None)

    try:
        if questions is not None:
            for item in questions:
                print(f"\n\033[1m> {item}\033[0m", flush=True)
                turn, history = controller.process_message(item, history)
                show_turn(turn)
            return 0

        print("Interactive. Ctrl-D to exit.\n")
        while True:
            try:
                item = input("\033[1m> \033[0m").strip()
            except EOFError:
                print()
                return 0
            if not item:
                continue
            turn, history = controller.process_message(item, history)
            show_turn(turn)
    except ConfigurationError as exc:
        print(f"\nSetup incomplete: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
