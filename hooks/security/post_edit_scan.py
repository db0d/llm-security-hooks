#!/usr/bin/env python3.14
"""postToolUse: file scanners for edits (SAST/secrets/deps/docker files)."""

from __future__ import annotations

import json
from pathlib import Path

from common import (
    HOOKS_ROOT,
    emit,
    extract_edit_path,
    find_project_root,
    format_findings_for_agent,
    is_compose_file,
    is_dep_manifest,
    is_dockerfile,
    is_opengrep_target,
    load_state,
    log,
    open_findings,
    read_stdin_json,
    run_compose_lint,
    run_hadolint,
    run_opengrep,
    run_trufflehog,
    run_uv_audit,
    save_state,
    track_edit,
    upsert_findings,
)


def parse_tool_input(raw: object) -> dict:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _append_open(
    agent_bits: list[str],
    state: dict,
    *,
    tool: str,
    file_path: str,
    header: str,
) -> None:
    open_only = [
        f
        for f in open_findings(state)
        if f.get("tool") == tool and f.get("file") == file_path
    ]
    if open_only:
        agent_bits.append(format_findings_for_agent(open_only, header=header))


def main() -> int:
    payload = read_stdin_json()
    conversation_id = str(payload.get("conversation_id") or "unknown")
    tool_name = str(payload.get("tool_name") or "")
    tool_input = parse_tool_input(payload.get("tool_input"))
    file_path = extract_edit_path(tool_name, tool_input)

    if not file_path:
        emit({})
        return 0

    path = Path(file_path)
    if not path.exists():
        emit({})
        return 0

    # Avoid recursively scanning the security hook implementation itself.
    try:
        path.resolve().relative_to(HOOKS_ROOT)
        emit({})
        return 0
    except ValueError:
        pass

    state = load_state(conversation_id)
    track_edit(state, str(path), list(payload.get("workspace_roots") or []))

    agent_bits: list[str] = []

    if is_dockerfile(str(path)):
        findings = run_hadolint(str(path))
        upsert_findings(
            state, tool="hadolint", new_findings=findings, scope_files=[str(path)]
        )
        _append_open(
            agent_bits,
            state,
            tool="hadolint",
            file_path=str(path),
            header="hadolint Dockerfile findings on the file just edited:",
        )
        log(f"hadolint {path} findings={len(findings)}", conversation_id=conversation_id)

    if is_compose_file(str(path)):
        findings = run_compose_lint(str(path))
        upsert_findings(
            state, tool="compose-lint", new_findings=findings, scope_files=[str(path)]
        )
        _append_open(
            agent_bits,
            state,
            tool="compose-lint",
            file_path=str(path),
            header="compose-lint findings on the Compose file just edited:",
        )
        log(
            f"compose-lint {path} findings={len(findings)}",
            conversation_id=conversation_id,
        )

    if is_opengrep_target(str(path)):
        og = run_opengrep(str(path))
        upsert_findings(
            state, tool="opengrep", new_findings=og, scope_files=[str(path)]
        )
        open_only = [
            f
            for f in open_findings(state)
            if f.get("tool") == "opengrep" and f.get("file") == str(path)
        ]
        if open_only:
            agent_bits.append(
                format_findings_for_agent(
                    open_only,
                    header="OpenGrep security findings on the file just edited:",
                )
            )
        log(f"opengrep {path} findings={len(og)}", conversation_id=conversation_id)

    # Secrets: scan any edited file that exists as a regular file
    if path.is_file():
        secrets = run_trufflehog(str(path))
        upsert_findings(
            state, tool="trufflehog", new_findings=secrets, scope_files=[str(path)]
        )
        open_only = [
            f
            for f in open_findings(state)
            if f.get("tool") == "trufflehog" and f.get("file") == str(path)
        ]
        if open_only:
            agent_bits.append(
                format_findings_for_agent(
                    open_only,
                    header="TruffleHog secret findings on the file just edited:",
                )
            )
        log(
            f"trufflehog {path} findings={len(secrets)}",
            conversation_id=conversation_id,
        )

    if is_dep_manifest(str(path)):
        project = find_project_root(path)
        if project is not None:
            vulns = run_uv_audit(project)
            upsert_findings(
                state,
                tool="uv-audit",
                new_findings=vulns,
                scope_files=[str(project / "pyproject.toml"), str(path)],
            )
            open_only = [
                f
                for f in open_findings(state)
                if f.get("tool") == "uv-audit" and f.get("status") == "open"
            ]
            if open_only:
                agent_bits.append(
                    format_findings_for_agent(
                        open_only,
                        header="uv audit dependency vulnerabilities:",
                    )
                )
            log(
                f"uv-audit {project} findings={len(vulns)}",
                conversation_id=conversation_id,
            )

    save_state(state)

    if agent_bits:
        emit({"additional_context": "\n\n".join(agent_bits)})
    else:
        emit({})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
