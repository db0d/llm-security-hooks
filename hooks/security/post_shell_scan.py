#!/usr/bin/env python3.14
"""postToolUse(Shell): Trivy image scan after successful local docker/podman builds."""

from __future__ import annotations

import json
from typing import Any

from common import (
    emit,
    format_findings_for_agent,
    load_state,
    log,
    looks_like_image_build,
    open_findings,
    read_stdin_json,
    resolve_built_images,
    run_trivy_image,
    save_state,
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


def parse_tool_output(raw: object) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {"stdout": raw}
        except json.JSONDecodeError:
            return {"stdout": raw}
    return {}


def shell_failed(tool_output: dict[str, Any]) -> bool:
    for key in ("exitCode", "exit_code", "code"):
        if key in tool_output:
            try:
                return int(tool_output[key]) != 0
            except (TypeError, ValueError):
                break
    if tool_output.get("isError") or tool_output.get("error"):
        return True
    return False


def shell_text(tool_output: dict[str, Any]) -> str:
    chunks: list[str] = []
    for key in ("stdout", "stderr", "output"):
        value = tool_output.get(key)
        if isinstance(value, str) and value:
            chunks.append(value)
    return "\n".join(chunks)


def main() -> int:
    payload = read_stdin_json()
    conversation_id = str(payload.get("conversation_id") or "unknown")
    tool_input = parse_tool_input(payload.get("tool_input"))
    tool_output = parse_tool_output(payload.get("tool_output"))
    command = str(tool_input.get("command") or "")
    cwd = tool_input.get("working_directory") or tool_input.get("cwd") or payload.get("cwd")
    cwd = str(cwd) if cwd else None

    if not looks_like_image_build(command) or shell_failed(tool_output):
        emit({})
        return 0

    images = resolve_built_images(command, output=shell_text(tool_output), cwd=cwd)
    if not images:
        log(f"trivy skip: no local images for: {command[:160]}", conversation_id=conversation_id)
        emit({})
        return 0

    state = load_state(conversation_id)
    if payload.get("workspace_roots"):
        state["workspace_roots"] = payload.get("workspace_roots")

    tracked = state.setdefault("docker_images", [])
    scanned = state.setdefault("trivy_scanned", [])
    agent_bits: list[str] = []

    for image in images:
        if image not in tracked:
            tracked.append(image)
        findings = run_trivy_image(image)
        upsert_findings(
            state,
            tool="trivy",
            new_findings=findings,
            scope_files=[image],
            scope_tool_only=True,
        )
        if image not in scanned:
            scanned.append(image)
        open_only = [
            f
            for f in open_findings(state)
            if f.get("tool") == "trivy" and f.get("file") == image
        ]
        log(
            f"trivy image={image} findings={len(findings)}",
            conversation_id=conversation_id,
        )
        if open_only:
            agent_bits.append(
                format_findings_for_agent(
                    open_only,
                    header=f"Trivy HIGH/CRITICAL findings for image `{image}`:",
                )
            )

    save_state(state)
    if agent_bits:
        emit({"additional_context": "\n\n".join(agent_bits)})
    else:
        emit({})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
