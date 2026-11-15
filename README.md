# llm-security-hooks

Security hooks for LLM coding agents — **Cursor first**, designed to expand to other agent platforms later.

These hooks inject scanner findings back into the agent context so issues can be fixed in-loop, then summarize **addressed + still open** findings for you at session end.

## What runs

| Scanner | When | Target |
|---|---|---|
| **OpenGrep** | After file edits | Python + GitHub Actions rule packs |
| **TruffleHog** | After file edits | Secrets in edited files |
| **uv audit** | When `pyproject.toml` / `uv.lock` change | SCA / dependency vulns |
| **hadolint** | Dockerfile edits | Dockerfile best practices |
| **compose-lint** | Compose file edits | Docker Compose security |
| **Trivy** | After successful `docker`/`podman`/`compose` builds | HIGH/CRITICAL image vulns (local images only) |
| **CodeQL** | Agent stop (once per session) | Python + GitHub Actions |

## Requirements

- Python **3.14+** (installer enforces this)
- Cursor IDE (user and/or project hooks)
- Optional: Docker Engine/Desktop for Trivy image scans

## Quick start

```bash
git clone https://github.com/db0d/llm-security-hooks.git
cd llm-security-hooks
chmod +x install.sh

# Interactive: prompts before installing missing tools
./install.sh

# Non-interactive
./install.sh --yes

# Project-local hooks (also supported)
./install.sh --project /path/to/your/repo

# Dependencies only / hooks only
./install.sh --deps-only --yes
./install.sh --hooks-only --user
```

### Install modes

| Flag | Destination |
|---|---|
| `--user` (default) | `~/.cursor/hooks.json` + `~/.cursor/hooks/security/` |
| `--project [DIR]` | `DIR/.cursor/hooks.json` + `DIR/.cursor/hooks/security/` |

Existing `hooks.json` files are backed up before overwrite.

## Supported installer platforms

- **macOS** (Homebrew)
- **Debian / Ubuntu** (`apt` + upstream binaries / `uv`)
- **Alpine** (`apk` + upstream binaries / `uv`)

## Verify

1. Reload Cursor (or reopen the window).
2. Open **Cursor Settings → Hooks** and confirm the security hooks are listed.
3. Logs (user install): `~/.cursor/hooks/security/logs/`
4. Session reports: `~/.cursor/hooks/security/reports/`

## Layout

```
hooks/security/          # Cursor hook scripts
templates/               # user + project hooks.json templates
install.sh               # cross-platform installer
```

## License

MIT
