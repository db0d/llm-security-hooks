#!/usr/bin/env python3.14
"""Initialize per-conversation security hook state."""

from __future__ import annotations

from common import emit, load_state, log, read_stdin_json, save_state, utc_now


def main() -> int:
    payload = read_stdin_json()
    conversation_id = str(
        payload.get("session_id")
        or payload.get("conversation_id")
        or "unknown"
    )
    state = load_state(conversation_id)
    state["conversation_id"] = conversation_id
    state["workspace_roots"] = payload.get("workspace_roots") or state.get("workspace_roots") or []
    state["started_at"] = utc_now()
    state["is_background_agent"] = bool(payload.get("is_background_agent"))
    save_state(state)
    log("sessionStart", conversation_id=conversation_id)
    emit(
        {
            "env": {
                "CURSOR_SECURITY_HOOKS": "1",
                "CURSOR_SECURITY_CONVERSATION_ID": conversation_id,
            },
            "additional_context": (
                "Security hooks are active: OpenGrep (Python + GitHub Actions), "
                "TruffleHog, uv audit on dependency changes, hadolint (Dockerfiles), "
                "compose-lint (Compose files), Trivy (local images after docker/podman "
                "build), and CodeQL (Python + Actions) at stop. Remediate injected "
                "findings promptly; the user gets fixed + open issues at session end."
            ),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
