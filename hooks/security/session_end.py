#!/usr/bin/env python3.14
"""sessionEnd: persist report + notify user (option B: fixed + still open)."""

from __future__ import annotations

from common import (
    emit,
    fixed_findings,
    format_user_summary,
    load_state,
    log,
    notify_macos,
    open_findings,
    read_stdin_json,
    save_state,
    write_report,
)


def main() -> int:
    payload = read_stdin_json()
    conversation_id = str(
        payload.get("session_id") or payload.get("conversation_id") or "unknown"
    )
    state = load_state(conversation_id)
    summary = format_user_summary(state)

    if not summary:
        log("sessionEnd no security issues tracked", conversation_id=conversation_id)
        emit({})
        return 0

    if not state.get("user_notified"):
        report = write_report(state, summary)
        fixed_n = len(fixed_findings(state))
        open_n = len(open_findings(state))
        notify_macos(
            "Cursor security hooks",
            f"{fixed_n} fixed, {open_n} open — {report.name}",
        )
        state["user_notified"] = True
        state["report_path"] = str(report)
        save_state(state)
        log(f"sessionEnd report={report}", conversation_id=conversation_id)

    emit({})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
