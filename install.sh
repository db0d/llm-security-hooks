#!/usr/bin/env bash
# llm-security-hooks installer
# Installs Cursor security hooks (user and/or project) and optional scanner deps.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
YES=0
DO_DEPS=1
DO_HOOKS=1
MODE="user" # user | project
PROJECT_DIR=""
ASSUME_TTY=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Install Cursor LLM security hooks and (optionally) scanner dependencies.

Options:
  --user                 Install into ~/.cursor (default)
  --project [DIR]        Install into DIR/.cursor (DIR defaults to current directory)
  --yes, -y              Non-interactive; auto-confirm dependency installs
  --deps-only            Only check/install dependencies
  --hooks-only           Only install hook files / hooks.json
  --help, -h             Show this help

Examples:
  ./install.sh
  ./install.sh --yes
  ./install.sh --project ~/code/my-app
  ./install.sh --deps-only -y
EOF
}

log() { printf '%s\n' "$*"; }
info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

confirm() {
  local prompt="$1"
  if [[ "$YES" -eq 1 ]]; then
    return 0
  fi
  if [[ ! -t 0 && "$ASSUME_TTY" -eq 0 ]]; then
    warn "non-interactive shell; pass --yes to auto-install: $prompt"
    return 1
  fi
  local reply
  read -r -p "$prompt [y/N] " reply
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

detect_os() {
  local uname_s
  uname_s="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$uname_s" in
    darwin) echo macos ;;
    linux)
      if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
          alpine) echo alpine ;;
          debian) echo debian ;;
          ubuntu) echo ubuntu ;;
          *)
            case "${ID_LIKE:-}" in
              *debian*) echo debian ;;
              *ubuntu*) echo ubuntu ;;
              *) echo linux-unknown ;;
            esac
            ;;
        esac
      else
        echo linux-unknown
      fi
      ;;
    *) echo unknown ;;
  esac
}

arch_norm() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) uname -m ;;
  esac
}

ensure_local_bin() {
  mkdir -p "${HOME}/.local/bin"
  case ":${PATH}:" in
    *":${HOME}/.local/bin:"*) ;;
    *) export PATH="${HOME}/.local/bin:${PATH}" ;;
  esac
}

python_ok() {
  have python3.14 || return 1
  python3.14 - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 14) else 1)
PY
}

install_python314() {
  local os="$1"
  info "Installing Python 3.14+"
  case "$os" in
    macos)
      if have brew; then
        brew install python@3.14 || brew install python
      else
        die "Homebrew is required on macOS to install Python 3.14 (https://brew.sh)"
      fi
      ;;
    debian|ubuntu)
      if have uv; then
        uv python install 3.14
        # Ensure python3.14 on PATH via uv's python dir / symlink into ~/.local/bin
        local py
        py="$(uv python find 3.14 2>/dev/null || true)"
        if [[ -n "$py" ]]; then
          ln -sfn "$py" "${HOME}/.local/bin/python3.14"
        fi
      else
        sudo apt-get update
        sudo apt-get install -y software-properties-common curl ca-certificates
        # Prefer uv bootstrap for a reliable 3.14 even on older distros
        curl -LsSf https://astral.sh/uv/install.sh | sh
        # shellcheck disable=SC1091
        [[ -f "${HOME}/.local/bin/env" ]] && . "${HOME}/.local/bin/env" || true
        ensure_local_bin
        uv python install 3.14
        local py
        py="$(uv python find 3.14 2>/dev/null || true)"
        if [[ -n "$py" ]]; then
          ln -sfn "$py" "${HOME}/.local/bin/python3.14"
        fi
      fi
      ;;
    alpine)
      if have uv; then
        uv python install 3.14
        local py
        py="$(uv python find 3.14 2>/dev/null || true)"
        [[ -n "$py" ]] && ln -sfn "$py" "${HOME}/.local/bin/python3.14"
      else
        # Bootstrap uv then install CPython 3.14
        apk add --no-cache curl bash ca-certificates
        curl -LsSf https://astral.sh/uv/install.sh | sh
        ensure_local_bin
        uv python install 3.14
        local py
        py="$(uv python find 3.14 2>/dev/null || true)"
        [[ -n "$py" ]] && ln -sfn "$py" "${HOME}/.local/bin/python3.14"
      fi
      ;;
    *)
      die "Unsupported OS for Python install: $os (install python3.14 manually, then re-run)"
      ;;
  esac
  python_ok || die "Python 3.14+ is still missing after install attempts"
}

install_uv() {
  local os="$1"
  info "Installing uv"
  case "$os" in
    macos)
      if have brew; then brew install uv; else curl -LsSf https://astral.sh/uv/install.sh | sh; fi
      ;;
    debian|ubuntu|alpine|*)
      curl -LsSf https://astral.sh/uv/install.sh | sh
      ;;
  esac
  ensure_local_bin
  # shellcheck disable=SC1091
  [[ -f "${HOME}/.local/bin/env" ]] && . "${HOME}/.local/bin/env" || true
  have uv || die "uv install failed"
}

install_jq() {
  local os="$1"
  info "Installing jq"
  case "$os" in
    macos) brew install jq ;;
    debian|ubuntu) sudo apt-get update && sudo apt-get install -y jq ;;
    alpine) sudo apk add --no-cache jq || apk add --no-cache jq ;;
    *) die "Install jq manually for OS=$os" ;;
  esac
}

install_hadolint() {
  local os="$1" arch
  arch="$(arch_norm)"
  info "Installing hadolint"
  case "$os" in
    macos) brew install hadolint ;;
    debian|ubuntu|alpine|*)
      local asset
      case "$arch" in
        amd64) asset="hadolint-Linux-x86_64" ;;
        arm64) asset="hadolint-Linux-arm64" ;;
        *) die "Unsupported arch for hadolint: $arch" ;;
      esac
      local url
      url="$(curl -fsSL https://api.github.com/repos/hadolint/hadolint/releases/latest \
        | python3.14 -c "import sys,json; d=json.load(sys.stdin); print(next(a['browser_download_url'] for a in d['assets'] if a['name']=='$asset'))")"
      curl -fsSL "$url" -o "${HOME}/.local/bin/hadolint"
      chmod +x "${HOME}/.local/bin/hadolint"
      ;;
  esac
  have hadolint || die "hadolint install failed"
}

install_trivy() {
  local os="$1"
  info "Installing trivy"
  case "$os" in
    macos) brew install trivy ;;
    debian|ubuntu)
      sudo apt-get update
      sudo apt-get install -y wget apt-transport-https gnupg lsb-release
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
      echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        | sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null
      sudo apt-get update && sudo apt-get install -y trivy
      ;;
    alpine)
      # Official binary install
      curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b "${HOME}/.local/bin"
      ;;
    *) die "Install trivy manually for OS=$os" ;;
  esac
  have trivy || die "trivy install failed"
}

install_trufflehog() {
  local os="$1"
  info "Installing trufflehog"
  case "$os" in
    macos) brew install trufflehog ;;
    debian|ubuntu|alpine|*)
      curl -fsSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b "${HOME}/.local/bin"
      ;;
  esac
  have trufflehog || die "trufflehog install failed"
}

install_opengrep() {
  local os="$1" arch
  arch="$(arch_norm)"
  info "Installing opengrep"
  case "$os" in
    macos)
      if brew install opengrep 2>/dev/null; then
        :
      else
        # Fallback: official installer / release asset via uv/pip not always available
        curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh \
          | bash || die "opengrep install failed (macOS). Install manually: https://opengrep.dev"
      fi
      ;;
    debian|ubuntu|alpine|*)
      if curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash; then
        :
      else
        die "opengrep install failed. See https://opengrep.dev"
      fi
      ;;
  esac
  ensure_local_bin
  have opengrep || die "opengrep not found on PATH after install"
}

install_codeql() {
  local os="$1"
  info "Installing CodeQL CLI"
  case "$os" in
    macos)
      brew install --cask codeql
      ;;
    debian|ubuntu|alpine|*)
      local version url tmp bundle
      # Official CLI bundles: linux64 / osx64 (x86_64). Linux arm64 users may need Rosetta/x86_64 userspace or manual install.
      bundle="linux64"
      if [[ "$(arch_norm)" == "arm64" ]]; then
        warn "CodeQL official linux arm64 bundle may be unavailable; attempting linux64"
      fi
      version="$(curl -fsSL https://api.github.com/repos/github/codeql-cli-binaries/releases/latest \
        | python3.14 -c 'import sys,json; print(json.load(sys.stdin)["tag_name"])')"
      url="https://github.com/github/codeql-cli-binaries/releases/download/${version}/codeql-${bundle}.zip"
      tmp="$(mktemp -d)"
      curl -fsSL "$url" -o "${tmp}/codeql.zip"
      rm -rf "${HOME}/.local/codeql"
      mkdir -p "${HOME}/.local/codeql"
      binary_path="$(
        python3.14 - <<PY
import zipfile
from pathlib import Path
root = Path("${HOME}/.local/codeql")
with zipfile.ZipFile("${tmp}/codeql.zip") as zf:
    zf.extractall(root)
binary = next((p for p in root.rglob("codeql") if p.is_file() and p.name == "codeql"), None)
if binary is None:
    raise SystemExit("codeql binary not found in extracted archive")
print(binary)
PY
      )"
      ln -sfn "$binary_path" "${HOME}/.local/bin/codeql"
      rm -rf "$tmp"
      ;;
  esac
  have codeql || die "codeql not found on PATH after install"
  # Prefetch query packs used by hooks
  codeql pack download codeql/python-queries codeql/actions-queries || warn "Could not prefetch CodeQL packs (will download on first use)"
}

install_compose_lint() {
  info "Installing compose-lint"
  if have pipx; then
    pipx install compose-lint || pipx upgrade compose-lint
  elif have uv; then
    uv tool install compose-lint
  else
    install_uv "$(detect_os)"
    uv tool install compose-lint
  fi
  ensure_local_bin
  have compose-lint || die "compose-lint not found on PATH after install"
}

maybe_install() {
  local name="$1" checker="$2" installer="$3" required="${4:-1}"
  if eval "$checker"; then
    log "  ✓ $name"
    return 0
  fi
  log "  ✗ $name (missing)"
  if [[ "$required" -eq 0 ]]; then
    if confirm "Install optional dependency $name?"; then
      eval "$installer"
    else
      warn "Skipping optional $name"
    fi
    return 0
  fi
  if confirm "Install missing dependency $name?"; then
    eval "$installer"
    eval "$checker" || die "$name still missing after install"
    log "  ✓ $name (installed)"
  else
    die "Required dependency $name was not installed"
  fi
}

install_dependencies() {
  local os
  os="$(detect_os)"
  info "Detected OS: $os ($(arch_norm))"
  ensure_local_bin

  case "$os" in
    macos)
      have brew || die "Homebrew is required on macOS (https://brew.sh)"
      ;;
    debian|ubuntu)
      have apt-get || die "apt-get not found"
      ;;
    alpine)
      have apk || die "apk not found"
      ;;
    *)
      warn "OS '$os' is not fully supported; attempting generic installs"
      ;;
  esac

  maybe_install "python3.14" "python_ok" "install_python314 '$os'" 1
  maybe_install "uv" "have uv" "install_uv '$os'" 1
  maybe_install "jq" "have jq" "install_jq '$os'" 1
  maybe_install "opengrep" "have opengrep" "install_opengrep '$os'" 1
  maybe_install "codeql" "have codeql" "install_codeql '$os'" 1
  maybe_install "trufflehog" "have trufflehog" "install_trufflehog '$os'" 1
  maybe_install "hadolint" "have hadolint" "install_hadolint '$os'" 1
  maybe_install "trivy" "have trivy" "install_trivy '$os'" 1
  maybe_install "compose-lint" "have compose-lint" "install_compose_lint" 1
  maybe_install "docker (optional, for Trivy image scans)" "have docker" "warn 'Install Docker Desktop / Engine manually: https://docs.docker.com/get-docker/'" 0

  info "Dependency check complete"
}

backup_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    local stamp
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    cp "$path" "${path}.bak.${stamp}"
    log "Backed up $path -> ${path}.bak.${stamp}"
  fi
}

sync_hook_scripts() {
  local src="$1" dest="$2"
  mkdir -p "$dest"
  local file
  for file in "$src"/*.py; do
    [[ -f "$file" ]] || continue
    cp "$file" "$dest/"
  done
  mkdir -p "${dest}/"{state,logs,reports,codeql-dbs}
  chmod +x "${dest}/"*.py 2>/dev/null || true
}

install_hooks_user() {
  local dest="${HOME}/.cursor"
  info "Installing user hooks into ${dest}"
  mkdir -p "${dest}/hooks/security"
  sync_hook_scripts "${ROOT}/hooks/security" "${dest}/hooks/security"
  backup_file "${dest}/hooks.json"
  cp "${ROOT}/templates/user-hooks.json" "${dest}/hooks.json"
  log "Wrote ${dest}/hooks.json"
}

install_hooks_project() {
  local project="${PROJECT_DIR:-$PWD}"
  mkdir -p "$project"
  project="$(cd "$project" && pwd)"
  local dest="${project}/.cursor"
  info "Installing project hooks into ${dest}"
  mkdir -p "${dest}/hooks/security"
  sync_hook_scripts "${ROOT}/hooks/security" "${dest}/hooks/security"
  backup_file "${dest}/hooks.json"
  cp "${ROOT}/templates/project-hooks.json" "${dest}/hooks.json"
  log "Wrote ${dest}/hooks.json"
  if [[ -f "${project}/.gitignore" ]] && ! grep -q '\.cursor/hooks/security/state' "${project}/.gitignore" 2>/dev/null; then
    cat >> "${project}/.gitignore" <<'EOF'

# llm-security-hooks runtime
.cursor/hooks/security/state/
.cursor/hooks/security/logs/
.cursor/hooks/security/reports/
.cursor/hooks/security/codeql-dbs/
.cursor/hooks/security/__pycache__/
EOF
    log "Appended runtime ignores to ${project}/.gitignore"
  fi
}

# --- args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) MODE="user"; shift ;;
    --project)
      MODE="project"
      if [[ $# -ge 2 && ! "$2" =~ ^-- ]]; then
        PROJECT_DIR="$2"
        shift 2
      else
        PROJECT_DIR="$PWD"
        shift
      fi
      ;;
    --yes|-y) YES=1; shift ;;
    --deps-only) DO_HOOKS=0; DO_DEPS=1; shift ;;
    --hooks-only) DO_HOOKS=1; DO_DEPS=0; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage; die "Unknown option: $1" ;;
  esac
done

info "llm-security-hooks installer"
log "Repo root: $ROOT"

if [[ "$DO_DEPS" -eq 1 ]]; then
  install_dependencies
fi

if [[ "$DO_HOOKS" -eq 1 ]]; then
  # Hooks require python3.14 even for hooks-only
  if ! python_ok; then
    if [[ "$DO_DEPS" -eq 1 ]] || confirm "Python 3.14+ is required for hooks. Install it now?"; then
      install_python314 "$(detect_os)"
    else
      die "Python 3.14+ is required"
    fi
  fi
  case "$MODE" in
    user) install_hooks_user ;;
    project) install_hooks_project ;;
    *) die "Unknown mode: $MODE" ;;
  esac
fi

info "Done"
log "Reload Cursor (or reopen the window) so hooks.json is picked up."
log "Verify under Cursor Settings → Hooks, and logs under ~/.cursor/hooks/security/logs/ (user install)."
