#!/usr/bin/env python3.14
"""stop: run CodeQL (Python + Actions) once, then follow up until issues are handled."""

from __future__ import annotations

from pathlib import Path

from common import (
    docker_image_exists,
    emit,
    format_findings_for_agent,
    format_user_summary,
    load_state,
    log,
    open_findings,
    read_stdin_json,
    run_codeql,
    run_trivy_image,
    save_state,
    upsert_findings,
    workspace_needs_codeql,
)


def primary_workspace(state: dict, payload: dict) -> Path | None:
    roots = payload.get("workspace_roots") or state.get("workspace_roots") or []
    for root in roots:
        path = Path(root)
        if path.is_dir():
            return path
    return None


def main() -> int:
    payload = read_stdin_json()
    conversation_id = str(payload.get("conversation_id") or "unknown")
    status = str(payload.get("status") or "")
    loop_count = int(payload.get("loop_count") or 0)

    state = load_state(conversation_id)
    if payload.get("workspace_roots"):
        state["workspace_roots"] = payload.get("workspace_roots")

    if status != "completed":
        save_state(state)
        emit({})
        return 0

    # Full CodeQL assessment once per conversation on first completed stop.
    if loop_count == 0 and not state.get("codeql_ran") and workspace_needs_codeql(state):
        root = primary_workspace(state, payload)
        if root is not None:
            log(f"codeql start root={root}", conversation_id=conversation_id)
            findings = run_codeql(root, conversation_id)
            upsert_findings(
                state,
                tool="codeql",
                new_findings=findings,
                scope_files=None,
                scope_tool_only=True,
            )
            # When scope_files is None, disappear logic skips file filter but still
            # tool-filters; first run has no prior codeql opens to close.
            state["codeql_ran"] = True
            state["codeql_finding_count"] = len(findings)
            log(f"codeql done findings={len(findings)}", conversation_id=conversation_id)
            save_state(state)

    # Catch any built images that exist locally but were not Trivy-scanned yet.
    if loop_count == 0:
        tracked = list(state.get("docker_images") or [])
        scanned = set(state.get("trivy_scanned") or [])
        for image in tracked:
            if image in scanned or not docker_image_exists(image):
                continue
            findings = run_trivy_image(image)
            upsert_findings(
                state,
                tool="trivy",
                new_findings=findings,
                scope_files=[image],
                scope_tool_only=True,
            )
            scanned.add(image)
            log(
                f"trivy(stop) image={image} findings={len(findings)}",
                conversation_id=conversation_id,
            )
        state["trivy_scanned"] = sorted(scanned)
        save_state(state)

    opened = open_findings(state)
    if opened and loop_count < 2:
        msg = format_findings_for_agent(
            opened,
            header=(
                "Security follow-up required before finishing. "
                "Resolve the open findings below, then stop."
            ),
        )
        save_state(state)
        emit({"followup_message": msg})
        return 0

    # Final stop path: ask the agent to surface option-B summary to the user once.
    summary = format_user_summary(state)
    if summary and not state.get("summary_followup_sent"):
        state["summary_followup_sent"] = True
        save_state(state)
        emit(
            {
                "followup_message": (
                    "Security scanning finished for this session. Paste the markdown "
                    "summary below to the user unchanged (do not rewrap into a prose "
                    "paragraph), then stop — do not continue coding unless they ask.\n\n"
                    f"{summary}"
                )
            }
        )
        return 0

    save_state(state)
    emit({})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
