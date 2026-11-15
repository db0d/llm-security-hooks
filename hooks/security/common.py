"""Shared helpers for Cursor security hooks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HOOKS_ROOT = Path(__file__).resolve().parent
STATE_DIR = HOOKS_ROOT / "state"
LOGS_DIR = HOOKS_ROOT / "logs"
REPORTS_DIR = HOOKS_ROOT / "reports"
CODEQL_DB_DIR = HOOKS_ROOT / "codeql-dbs"

OPENGREP_CONFIGS = ("p/python", "p/github-actions")
OPENGREP_SUFFIXES = {".py", ".pyi", ".yml", ".yaml"}
DEP_BASENAMES = {"pyproject.toml", "uv.lock"}
COMPOSE_BASENAMES = {
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}
WORKFLOW_RE = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", re.I)
DOCKER_BUILD_RE = re.compile(
    r"(?:^|[;&|]\s*|\n)\s*(?:sudo\s+)?(?:docker(?:\s+buildx)?|podman)\s+build\b",
    re.I,
)
COMPOSE_BUILD_RE = re.compile(
    r"(?:^|[;&|]\s*|\n)\s*(?:sudo\s+)?(?:docker\s+compose|docker-compose)\b[^\n]*\bbuild\b",
    re.I,
)
DOCKER_TAG_FLAG_RE = re.compile(r"(?:^|\s)(?:-t|--tag)(?:=|\s+)(\S+)")
DOCKER_TAGGED_RE = re.compile(r"Successfully tagged\s+(\S+)")
DOCKER_NAMING_RE = re.compile(r"naming to\s+(\S+)", re.I)

# Ensure local CLIs are visible to Cursor's hook environment.
_HOME = Path.home()
_EXTRA_PATH_PARTS = [
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    str(_HOME / ".local" / "bin"),
    str(_HOME / ".docker" / "bin"),
    "/Applications/Docker.app/Contents/Resources/bin",
]
os.environ["PATH"] = ":".join(_EXTRA_PATH_PARTS) + ":" + os.environ.get("PATH", "")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs() -> None:
    for path in (STATE_DIR, LOGS_DIR, REPORTS_DIR, CODEQL_DB_DIR):
        path.mkdir(parents=True, exist_ok=True)


def read_stdin_json() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    sys.stdout.flush()


def log(message: str, *, conversation_id: str | None = None) -> None:
    ensure_dirs()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    line = f"{utc_now()} [{conversation_id or '-'}] {message}\n"
    with (LOGS_DIR / f"security-{stamp}.log").open("a", encoding="utf-8") as fh:
        fh.write(line)


def which(binary: str) -> str | None:
    from shutil import which as _which

    return _which(binary)


def state_path(conversation_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", conversation_id or "unknown")
    return STATE_DIR / f"{safe}.json"


def load_state(conversation_id: str) -> dict[str, Any]:
    ensure_dirs()
    path = state_path(conversation_id)
    if not path.exists():
        return {
            "conversation_id": conversation_id,
            "created_at": utc_now(),
            "workspace_roots": [],
            "edited_files": [],
            "findings": {},
            "codeql_ran": False,
            "user_notified": False,
            "summary_followup_sent": False,
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "conversation_id": conversation_id,
            "created_at": utc_now(),
            "workspace_roots": [],
            "edited_files": [],
            "findings": {},
            "codeql_ran": False,
            "user_notified": False,
            "summary_followup_sent": False,
        }


def save_state(state: dict[str, Any]) -> None:
    ensure_dirs()
    conversation_id = str(state.get("conversation_id") or "unknown")
    path = state_path(conversation_id)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def finding_id(tool: str, rule: str, file_path: str, line: int | None, message: str) -> str:
    raw = f"{tool}|{rule}|{file_path}|{line or 0}|{message}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def upsert_findings(
    state: dict[str, Any],
    *,
    tool: str,
    new_findings: list[dict[str, Any]],
    scope_files: list[str] | None = None,
    scope_tool_only: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Merge scanner results. Findings in scope that disappear are marked fixed.

    Returns (opened_or_still_open, newly_fixed).
    """
    findings: dict[str, Any] = state.setdefault("findings", {})
    now = utc_now()
    seen_ids: set[str] = set()
    opened: list[dict[str, Any]] = []

    for item in new_findings:
        fid = item["id"]
        seen_ids.add(fid)
        existing = findings.get(fid)
        if existing:
            existing["last_seen"] = now
            existing["status"] = "open"
            existing["severity"] = item.get("severity", existing.get("severity"))
            existing["message"] = item.get("message", existing.get("message"))
            opened.append(existing)
        else:
            record = {
                **item,
                "status": "open",
                "first_seen": now,
                "last_seen": now,
                "fixed_at": None,
            }
            findings[fid] = record
            opened.append(record)

    newly_fixed: list[dict[str, Any]] = []
    scope = set(scope_files or [])
    for fid, existing in list(findings.items()):
        if existing.get("status") != "open":
            continue
        if scope_tool_only and existing.get("tool") != tool:
            continue
        if scope and existing.get("file") not in scope:
            continue
        if fid in seen_ids:
            continue
        existing["status"] = "fixed"
        existing["fixed_at"] = now
        newly_fixed.append(existing)

    return opened, newly_fixed


def open_findings(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for f in state.get("findings", {}).values() if f.get("status") == "open"]


def fixed_findings(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for f in state.get("findings", {}).values() if f.get("status") == "fixed"]


def track_edit(state: dict[str, Any], file_path: str, workspace_roots: list[str]) -> None:
    if workspace_roots:
        state["workspace_roots"] = workspace_roots
    edited = state.setdefault("edited_files", [])
    if file_path and file_path not in edited:
        edited.append(file_path)


def extract_edit_path(tool_name: str, tool_input: Any) -> str | None:
    if not isinstance(tool_input, dict):
        return None
    for key in ("path", "file_path", "filePath", "target_notebook"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return str(Path(value).expanduser())
    return None


def is_dockerfile(path: str) -> bool:
    name = Path(path).name
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return True
    if name.endswith(".Dockerfile"):
        return True
    return name.lower() == "dockerfile"


def is_compose_file(path: str) -> bool:
    name = Path(path).name.lower()
    if name in COMPOSE_BASENAMES:
        return True
    if name.endswith((".yml", ".yaml")) and (
        name.startswith("compose.") or name.startswith("docker-compose.")
    ):
        return True
    return False


def is_opengrep_target(path: str) -> bool:
    # Dockerfiles / Compose files have dedicated linters.
    if is_dockerfile(path) or is_compose_file(path):
        return False
    p = Path(path)
    if p.suffix.lower() in OPENGREP_SUFFIXES:
        return True
    return bool(WORKFLOW_RE.search(path.replace("\\", "/")))


def is_dep_manifest(path: str) -> bool:
    return Path(path).name in DEP_BASENAMES


def looks_like_image_build(command: str) -> bool:
    return bool(DOCKER_BUILD_RE.search(command) or COMPOSE_BUILD_RE.search(command))


def docker_image_exists(image: str) -> bool:
    binary = which("docker")
    if not binary or not image or image.endswith(":<none>"):
        return False
    try:
        proc = run_cmd([binary, "image", "inspect", image], timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def extract_docker_build_images(command: str, output: str = "") -> list[str]:
    """Best-effort image refs from docker/podman build -t flags and build output."""
    found: list[str] = []
    for match in DOCKER_TAG_FLAG_RE.finditer(command or ""):
        tag = match.group(1).strip().strip("'\"")
        if tag and tag not in found:
            found.append(tag)
    for pattern in (DOCKER_TAGGED_RE, DOCKER_NAMING_RE):
        for match in pattern.finditer(output or ""):
            tag = match.group(1).strip().rstrip(",")
            if tag.startswith("docker.io/library/"):
                tag = tag[len("docker.io/library/") :]
            if tag and tag not in found:
                found.append(tag)
    return found


def extract_compose_build_images(command: str, cwd: str | None) -> list[str]:
    """Resolve images for `docker compose build` via `compose config --images`."""
    binary = which("docker")
    if not binary:
        return []
    # Reuse the compose invocation prefix up to (but not including) build.
    match = re.search(
        r"((?:sudo\s+)?(?:docker\s+compose|docker-compose)\b.*?)(\bbuild\b)",
        command,
        re.I | re.S,
    )
    if not match:
        return []
    prefix = match.group(1).strip()
    # Avoid feeding build args into config; keep -f/--project-directory flags only.
    try:
        proc = run_cmd(
            ["bash", "-lc", f"{prefix} config --images"],
            cwd=cwd,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    images: list[str] = []
    for line in proc.stdout.splitlines():
        image = line.strip()
        if image and image not in images:
            images.append(image)
    return images


def resolve_built_images(
    command: str,
    *,
    output: str = "",
    cwd: str | None = None,
) -> list[str]:
    images = extract_docker_build_images(command, output)
    if COMPOSE_BUILD_RE.search(command):
        for image in extract_compose_build_images(command, cwd):
            if image not in images:
                images.append(image)
    # Only keep images that actually exist locally.
    return [image for image in images if docker_image_exists(image)]


def find_project_root(start: Path) -> Path | None:
    cur = start if start.is_dir() else start.parent
    for candidate in [cur, *cur.parents]:
        if (candidate / "pyproject.toml").exists() or (candidate / "uv.lock").exists():
            return candidate
    return None


def run_cmd(
    args: list[str],
    *,
    cwd: str | Path | None = None,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=merged,
        check=False,
    )


def _short_rule(rule: str) -> str:
    rule = str(rule or "rule")
    # Prefer the leaf of path- or dotted-style rule IDs.
    if "/" in rule or "\\" in rule:
        parts = [p for p in rule.replace("\\", "/").split("/") if p]
    else:
        parts = [p for p in rule.split(".") if p]
    return parts[-1] if parts else rule


def _display_path(file_path: str | None, workspace_roots: list[str] | None = None) -> str:
    if not file_path:
        return "(project)"
    path = Path(file_path)
    roots = [Path(r) for r in (workspace_roots or []) if r]
    for root in roots:
        try:
            return str(path.resolve().relative_to(root.resolve()))
        except (OSError, ValueError):
            continue
    # Prefer a compact home-relative path when absolute
    try:
        home = Path.home().resolve()
        resolved = path.expanduser().resolve()
        if resolved == home or home in resolved.parents:
            return "~/" + str(resolved.relative_to(home))
    except (OSError, ValueError):
        pass
    return str(path)


def _location(finding: dict[str, Any], workspace_roots: list[str] | None = None) -> str:
    loc = _display_path(finding.get("file"), workspace_roots)
    if finding.get("line"):
        return f"{loc}:{finding['line']}"
    return loc


def _severity_label(severity: str | None) -> str:
    value = str(severity or "info").lower()
    mapping = {
        "error": "high",
        "high": "high",
        "warning": "medium",
        "medium": "medium",
        "note": "low",
        "info": "low",
        "low": "low",
        "critical": "critical",
    }
    return mapping.get(value, value)


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse duplicate tool/rule/file/message rows (keep first; track count)."""
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for finding in findings:
        key = "|".join(
            [
                str(finding.get("tool") or ""),
                str(finding.get("rule") or ""),
                str(finding.get("file") or ""),
                str(finding.get("message") or ""),
            ]
        )
        if key not in grouped:
            item = dict(finding)
            item["_count"] = 1
            grouped[key] = item
            order.append(key)
        else:
            grouped[key]["_count"] = int(grouped[key].get("_count") or 1) + 1
            # Prefer a concrete line number if later rows have one
            if not grouped[key].get("line") and finding.get("line"):
                grouped[key]["line"] = finding.get("line")
    return [grouped[key] for key in order]


def _truncate(text: str, limit: int = 120) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _format_finding_line(
    finding: dict[str, Any],
    *,
    workspace_roots: list[str] | None = None,
) -> str:
    tool = str(finding.get("tool") or "scanner")
    severity = _severity_label(finding.get("severity"))
    rule = _short_rule(str(finding.get("rule") or "rule"))
    loc = _location(finding, workspace_roots)
    count = int(finding.get("_count") or 1)
    count_bit = f" ×{count}" if count > 1 else ""
    message = _truncate(str(finding.get("message") or "").strip(), 100)
    detail = f" — {message}" if message else ""
    return f"- `{tool}` {severity} `{rule}` @ `{loc}`{count_bit}{detail}"


def format_findings_for_agent(findings: list[dict[str, Any]], *, header: str) -> str:
    if not findings:
        return ""
    deduped = _dedupe_findings(findings)
    lines = [
        header,
        "Fix these before continuing unrelated work. Ask the user only if a secret must be rotated outside the repo.",
        "",
    ]
    for finding in deduped[:20]:
        lines.append(_format_finding_line(finding))
    if len(deduped) > 20:
        lines.append(f"- …and {len(deduped) - 20} more")
    return "\n".join(lines).rstrip() + "\n"


def format_user_summary(state: dict[str, Any]) -> str:
    fixed_raw = fixed_findings(state)
    open_raw = open_findings(state)
    if not fixed_raw and not open_raw:
        return ""

    fixed = _dedupe_findings(fixed_raw)
    opened = _dedupe_findings(open_raw)
    roots = list(state.get("workspace_roots") or [])
    fixed_total = sum(int(f.get("_count") or 1) for f in fixed)
    open_total = sum(int(f.get("_count") or 1) for f in opened)

    if open_total == 0:
        headline = f"All clear — {fixed_total} addressed, 0 open."
    elif fixed_total == 0:
        headline = f"{open_total} still open."
    else:
        headline = f"{fixed_total} addressed, {open_total} still open."

    lines = [
        "## Security scan summary",
        "",
        headline,
        "",
    ]

    lines.append(f"### Addressed ({fixed_total})")
    if fixed:
        for finding in fixed[:15]:
            lines.append(_format_finding_line(finding, workspace_roots=roots))
        if len(fixed) > 15:
            lines.append(f"- …and {len(fixed) - 15} more")
    else:
        lines.append("- None")
    lines.append("")

    lines.append(f"### Still open ({open_total})")
    if opened:
        for finding in opened[:15]:
            lines.append(_format_finding_line(finding, workspace_roots=roots))
        if len(opened) > 15:
            lines.append(f"- …and {len(opened) - 15} more")
    else:
        lines.append("- None")

    return "\n".join(lines).rstrip() + "\n"


def notify_macos(title: str, body: str) -> None:
    # Keep notification text short; full detail lives in the report file.
    safe_title = title.replace('"', '\\"')
    safe_body = body.replace('"', '\\"')[:180]
    try:
        run_cmd(
            [
                "osascript",
                "-e",
                f'display notification "{safe_body}" with title "{safe_title}"',
            ],
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def write_report(state: dict[str, Any], summary: str) -> Path:
    ensure_dirs()
    conversation_id = str(state.get("conversation_id") or "unknown")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORTS_DIR / f"{stamp}-{conversation_id[:8]}.md"
    path.write_text(summary + "\n", encoding="utf-8")
    return path


def run_opengrep(file_path: str) -> list[dict[str, Any]]:
    binary = which("opengrep")
    if not binary:
        return []
    args = [binary, "scan", "--json", "--quiet"]
    for config in OPENGREP_CONFIGS:
        args.extend(["--config", config])
    args.append(file_path)
    try:
        proc = run_cmd(args, timeout=45)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if not proc.stdout.strip():
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    results: list[dict[str, Any]] = []
    for result in payload.get("results", []) or []:
        check_id = str(result.get("check_id") or "opengrep")
        path = str(result.get("path") or file_path)
        start = (result.get("start") or {}) if isinstance(result.get("start"), dict) else {}
        line = start.get("line")
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        message = str(extra.get("message") or result.get("message") or check_id)
        severity = str(extra.get("severity") or "WARNING").lower()
        fid = finding_id("opengrep", check_id, path, line, message)
        results.append(
            {
                "id": fid,
                "tool": "opengrep",
                "severity": severity,
                "rule": check_id,
                "file": path,
                "line": line,
                "message": message,
            }
        )
    return results


def run_hadolint(file_path: str) -> list[dict[str, Any]]:
    binary = which("hadolint")
    if not binary or not Path(file_path).is_file():
        return []
    try:
        proc = run_cmd(
            [binary, "-f", "json", "--no-fail", file_path],
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if not proc.stdout.strip():
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    results: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "hadolint")
        message = str(item.get("message") or code)
        severity = str(item.get("level") or "info").lower()
        line = item.get("line")
        path = str(item.get("file") or file_path)
        if path == "-":
            path = file_path
        fid = finding_id("hadolint", code, path, line, message)
        results.append(
            {
                "id": fid,
                "tool": "hadolint",
                "severity": severity,
                "rule": code,
                "file": path,
                "line": line,
                "message": message,
            }
        )
    return results


def run_compose_lint(file_path: str) -> list[dict[str, Any]]:
    binary = which("compose-lint")
    if not binary or not Path(file_path).is_file():
        return []
    try:
        proc = run_cmd(
            [binary, "check", "--format", "json", "--fail-on", "critical", file_path],
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = proc.stdout.strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        return []
    results: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict) or item.get("suppressed"):
            continue
        rule = str(item.get("rule_id") or "compose-lint")
        message = str(item.get("message") or rule)
        service = item.get("service")
        if service:
            message = f"service {service}: {message}"
        severity = str(item.get("severity") or "medium").lower()
        line = item.get("line")
        path = str(item.get("file") or file_path)
        fid = finding_id("compose-lint", rule, path, line, message)
        results.append(
            {
                "id": fid,
                "tool": "compose-lint",
                "severity": severity,
                "rule": rule,
                "file": path,
                "line": line,
                "message": message,
            }
        )
    return results


def run_trivy_image(image: str, *, max_findings: int = 20) -> list[dict[str, Any]]:
    binary = which("trivy")
    if not binary or not image:
        return []
    if not docker_image_exists(image):
        return []
    args = [
        binary,
        "image",
        "--quiet",
        "--format",
        "json",
        "--severity",
        "HIGH,CRITICAL",
        "--scanners",
        "vuln",
        image,
    ]
    try:
        proc = run_cmd(args, timeout=240)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if not proc.stdout.strip():
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    results: list[dict[str, Any]] = []
    for block in payload.get("Results") or []:
        if not isinstance(block, dict):
            continue
        for vuln in block.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("VulnerabilityID") or "CVE")
            pkg = str(vuln.get("PkgName") or vuln.get("PackageName") or "package")
            severity = str(vuln.get("Severity") or "HIGH").lower()
            title = str(vuln.get("Title") or vuln.get("Description") or vuln_id)
            message = _truncate(f"{pkg}: {title}", 120)
            fid = finding_id("trivy", vuln_id, image, None, message)
            results.append(
                {
                    "id": fid,
                    "tool": "trivy",
                    "severity": severity,
                    "rule": vuln_id,
                    "file": image,
                    "line": None,
                    "message": message,
                }
            )
            if len(results) >= max_findings:
                return results
    return results


def run_trufflehog(file_path: str) -> list[dict[str, Any]]:
    binary = which("trufflehog")
    if not binary or not Path(file_path).is_file():
        return []
    args = [
        binary,
        "filesystem",
        "--json",
        "--no-update",
        "--no-verification",
        "--results=verified,unverified,unknown",
        file_path,
    ]
    try:
        proc = run_cmd(args, timeout=45)
    except (OSError, subprocess.TimeoutExpired):
        return []
    results: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = str(
            item.get("DetectorName")
            or (item.get("DetectorDescription") if isinstance(item.get("DetectorDescription"), str) else None)
            or "secret"
        )
        src = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        if not isinstance(src, dict):
            src = {}
        path = str(src.get("file") or file_path)
        line_no = src.get("line")
        raw = item.get("Raw") or item.get("RawV2") or ""
        preview = (raw[:12] + "…") if isinstance(raw, str) and len(raw) > 12 else "[redacted]"
        verified = bool(item.get("Verified"))
        message = f"Possible secret via {detector} (verified={verified}, preview={preview})"
        # Skip likely 1Password references
        if isinstance(raw, str) and raw.startswith("op://"):
            continue
        fid = finding_id("trufflehog", detector, path, line_no, detector)
        results.append(
            {
                "id": fid,
                "tool": "trufflehog",
                "severity": "error" if verified else "warning",
                "rule": detector,
                "file": path,
                "line": line_no,
                "message": message,
            }
        )
    return results


def run_uv_audit(project_root: Path) -> list[dict[str, Any]]:
    binary = which("uv")
    if not binary:
        return []
    try:
        proc = run_cmd(
            [binary, "audit", "--preview-features", "audit-command", "--output-format", "json"],
            cwd=project_root,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = proc.stdout.strip() or proc.stderr.strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # Fall back to treating non-empty non-json as opaque failure text only when exit != 0
        if proc.returncode == 0:
            return []
        fid = finding_id("uv-audit", "audit-failed", str(project_root / "pyproject.toml"), None, text[:200])
        return [
            {
                "id": fid,
                "tool": "uv-audit",
                "severity": "warning",
                "rule": "audit-failed",
                "file": str(project_root / "pyproject.toml"),
                "line": None,
                "message": text[:300],
            }
        ]

    vulns: list[Any]
    if isinstance(payload, dict):
        vulns = payload.get("vulnerabilities") or payload.get("vulns") or payload.get("findings") or []
        if not vulns and "dependencies" in payload:
            vulns = []
            for dep in payload.get("dependencies") or []:
                if isinstance(dep, dict):
                    for vuln in dep.get("vulnerabilities") or dep.get("vulns") or []:
                        if isinstance(vuln, dict):
                            vuln = {**vuln, "package": dep.get("name") or dep.get("package")}
                            vulns.append(vuln)
    elif isinstance(payload, list):
        vulns = payload
    else:
        vulns = []

    results: list[dict[str, Any]] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        vuln_id = str(vuln.get("id") or vuln.get("advisory") or vuln.get("cve") or "vuln")
        package = str(vuln.get("package") or vuln.get("name") or "dependency")
        summary = str(vuln.get("summary") or vuln.get("description") or vuln_id)
        severity = str(vuln.get("severity") or "warning").lower()
        message = f"{package}: {summary}"
        file_path = str(project_root / "pyproject.toml")
        fid = finding_id("uv-audit", vuln_id, file_path, None, message)
        results.append(
            {
                "id": fid,
                "tool": "uv-audit",
                "severity": severity,
                "rule": vuln_id,
                "file": file_path,
                "line": None,
                "message": message,
            }
        )
    return results


def workspace_needs_codeql(state: dict[str, Any]) -> bool:
    roots = [Path(r) for r in state.get("workspace_roots") or [] if r]
    edited = state.get("edited_files") or []
    for path in edited:
        suffix = Path(path).suffix.lower()
        if suffix in {".py", ".pyi"} or WORKFLOW_RE.search(str(path).replace("\\", "/")):
            return True
    for root in roots:
        if not root.is_dir():
            continue
        if any(root.glob("**/*.py")):
            return True
        if (root / ".github" / "workflows").is_dir():
            return True
    return False


def run_codeql(workspace_root: Path, conversation_id: str) -> list[dict[str, Any]]:
    binary = which("codeql")
    if not binary:
        log("codeql binary not found", conversation_id=conversation_id)
        return []

    languages: list[str] = []
    if any(workspace_root.glob("**/*.py")):
        languages.append("python")
    workflows = workspace_root / ".github" / "workflows"
    if workflows.is_dir() and (
        any(workflows.glob("*.yml")) or any(workflows.glob("*.yaml"))
    ):
        languages.append("actions")
    if not languages:
        return []

    db_key = hashlib.sha256(str(workspace_root.resolve()).encode("utf-8")).hexdigest()[:12]
    db_cluster = CODEQL_DB_DIR / f"{db_key}-cluster"

    create_args = [
        binary,
        "database",
        "create",
        str(db_cluster),
        "--db-cluster",
        f"--language={','.join(languages)}",
        f"--source-root={workspace_root}",
        "--overwrite",
    ]
    try:
        create = run_cmd(create_args, timeout=420)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"codeql create failed: {exc}", conversation_id=conversation_id)
        return []
    if create.returncode != 0:
        log(
            f"codeql create rc={create.returncode}: {create.stderr[-500:]}",
            conversation_id=conversation_id,
        )
        return []

    suite_by_lang = {
        "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
        "actions": "codeql/actions-queries:codeql-suites/actions-security-extended.qls",
    }

    results: list[dict[str, Any]] = []
    for lang in languages:
        db_path = db_cluster / lang
        if not db_path.is_dir():
            log(f"codeql missing db for {lang}", conversation_id=conversation_id)
            continue
        sarif_path = CODEQL_DB_DIR / f"{db_key}-{lang}-{conversation_id[:8]}.sarif"
        analyze_args = [
            binary,
            "database",
            "analyze",
            str(db_path),
            suite_by_lang[lang],
            "--format=sarif-latest",
            f"--output={sarif_path}",
        ]
        try:
            analyze = run_cmd(analyze_args, timeout=420)
        except (OSError, subprocess.TimeoutExpired) as exc:
            log(f"codeql analyze {lang} failed: {exc}", conversation_id=conversation_id)
            continue
        if not sarif_path.exists():
            log(
                f"codeql analyze {lang} rc={analyze.returncode}: {analyze.stderr[-500:]}",
                conversation_id=conversation_id,
            )
            continue
        try:
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for run in sarif.get("runs", []) or []:
            for result in run.get("results", []) or []:
                rule_id = str(result.get("ruleId") or "codeql")
                message_obj = result.get("message") if isinstance(result.get("message"), dict) else {}
                message = str(message_obj.get("text") or rule_id)
                severity = str(result.get("level") or "warning").lower()
                file_path = str(workspace_root)
                line = None
                locations = result.get("locations") or []
                if locations and isinstance(locations[0], dict):
                    phys = (
                        locations[0]
                        .get("physicalLocation", {})
                        .get("artifactLocation", {})
                    )
                    uri = phys.get("uri") if isinstance(phys, dict) else None
                    if uri:
                        candidate = Path(uri)
                        file_path = str(
                            candidate if candidate.is_absolute() else workspace_root / candidate
                        )
                    region = locations[0].get("physicalLocation", {}).get("region", {})
                    if isinstance(region, dict):
                        line = region.get("startLine")
                fid = finding_id("codeql", rule_id, file_path, line, message)
                results.append(
                    {
                        "id": fid,
                        "tool": "codeql",
                        "severity": severity,
                        "rule": rule_id,
                        "file": file_path,
                        "line": line,
                        "message": message,
                    }
                )
    return results


def sleep_brief() -> None:
    # Tiny yield so rapid sequential hooks don't clobber state writes.
    time.sleep(0.01)
