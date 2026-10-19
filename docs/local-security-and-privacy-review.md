# Local Security, Privacy & System Footprint Review

This document provides a code-verified review of **Claude Command Center (CCC)** covering three core questions:

1. [Is it safe to run locally?](#1-is-it-safe-to-run-locally)
2. [Is the data stored only locally?](#2-is-the-data-stored-only-locally)
3. [Are any system files or permissions modified?](#3-are-any-system-files-or-permissions-modified)

---

## 1. Is It Safe to Run Locally?

**Short answer:** Yes for single-user local development, provided you understand its threat model: **CCC is a high-privilege local orchestrator with no authentication on `127.0.0.1`**. Any process or user on your machine that can reach `http://127.0.0.1:8090` effectively has your OS user’s privileges. (For an authenticated, reverse-proxied setup, see [`docs/hardened-deploy.md`](hardened-deploy.md).)

### Security Controls in Place

* **Loopback-only binding by default:** [`main()`](../server.py#L42623-L42632) binds strictly to `127.0.0.1:8090` unless you explicitly set `CCC_BIND_HOST=0.0.0.0` (which prints a warning; see [`SECURITY.md`](../SECURITY.md#L5-L21)).
* **CSRF / Same-Origin check on `POST`:** [`_check_same_origin()`](../server.py#L31600-L31637) rejects browser cross-origin `POST` requests from non-local origins (`Origin` / `Referer` must be absent or match `localhost`, `127.0.0.1`, `[::1]`, or an active remote-access session).
* **Safe subprocess invocation:** Subprocesses (`git`, `claude`, `codex`, `gh`, `tmux`, etc.) are invoked using argument arrays without `shell=True`.
* **Strict file creation mask:** [`main()`](../server.py#L42459) sets `os.umask(0o077)` at startup so newly created state, log, and secret files default to owner-only (`0600`/`0700`).

### Local Risks & Quirks to Be Aware Of

* **Unauthenticated local API & `--dangerously-skip-permissions`:** By design ([`SECURITY.md`](../SECURITY.md#L11)), spawned headless agents (`claude`, `codex`, etc.) run with permission prompts bypassed so they do not hang in the background. Any local script (or another local web server running on `localhost:*`, which passes `_check_same_origin`) can call `/api/sessions/spawn` or `/api/open` to run commands or open files as your user.
* **Background idle process reaper:** [`_idle_reaper_loop()`](../server.py#L42695-L42698) runs every 30 minutes and sends `SIGTERM` to `claude` processes whose JSONL transcript has been inactive for >24 hours.
* **Hardcoded maintainer iMessage poller (`_chuck_imessage_poller`):** [`server.py`](../server.py#L42701-L42703) unconditionally starts [`_chuck_imessage_poller()`](../server.py#L42819-L42930) as a daemon thread. Every 120 seconds, if `~/Library/Messages/chat.db` exists and your terminal/Python binary has macOS **Full Disk Access**, it queries `chat.db` for messages from a hardcoded phone number (`+17035592946`), writes `/tmp/chuck-loop-last-seen.txt`, and attempts to forward matches into a hardcoded session UUID (`b1216dcf-99b2-48bf-85af-cb0ecea4f1ca`). It is a no-op if `chat.db` is unreadable or that contact/session does not exist, but it is a maintainer-specific artifact running in the default server loop.

---

## 2. Is the Data Stored Only Locally?

**Short answer:** All session transcripts, SQLite/FTS indexes, settings, and secrets are **stored locally** in your home directory, **but CCC makes several outbound network calls by default** (telemetry beacon, WatchTower auto-install, model/pricing doc fetches, and provider quota checks).

### Local Storage Locations

* **`~/.claude/command-center/`**: Primary state directory ([`ccc_server/paths.py`](../ccc_server/paths.py#L22-L67)) holding session metadata, SQLite indexes (`sessions-index.db`, `usage.db`), settings, attachments, hook scripts, backups, and `secrets/` (`0700`).
* **`~/.claude/projects/` & `~/.codex/`**: Reads (and via spawned CLIs, writes) Claude Code and Codex session transcripts.
* **`~/.config/claude-command-center/`**: Stores `telemetry-last-open` (`0600` in `0700` dir).
* **`~/.ccc/` & `~/.watchtower/`**: Created when `run.sh` installs/runs WatchTower or managed installs.

### Outbound Network Calls Made **By Default**

1. **Anonymous Daily Telemetry Beacon:**
   * [`_start_telemetry_thread()`](../ccc_server/fleet_jobs.py#L2136-L2155) (started in [`server.py`](../server.py#L42726)) waits 30s after startup and sends at most one `POST` per UTC day to `https://telemetry.claude-command-center.workers.dev/v1/open`.
   * Payload ([`_build_telemetry_payload()`](../ccc_server/fleet_jobs.py#L1988-L2020)): `{schema_version: 2, version, platform, first_this_week, first_this_month}`. No prompts, file paths, or persistent install IDs are sent (see [`docs/telemetry.md`](telemetry.md)).
   * **Disable with:** `CCC_TELEMETRY_DISABLED=1`
2. **WatchTower Auto-Clone & Daily Update (`./run.sh`):**
   * On startup, [`run.sh`](../run.sh#L816-L842) runs [`scripts/install-watchtower.sh`](../scripts/install-watchtower.sh#L411-L534) if `watchtower` is not installed, cloning `https://github.com/amirfish1/watchtower` (or downloading from GitHub/PyPI) and checking for updates daily.
   * **Disable with:** `CCC_SKIP_WATCHTOWER=1`
3. **Provider Quota Polling (Every 5 Minutes):**
   * [`_start_plan_usage_poller()`](../server.py#L42706) ([`ccc_server/recall_usage.py`](../ccc_server/recall_usage.py#L53-L315)) reads your existing Claude credentials (from `$CLAUDE_CODE_OAUTH_TOKEN`, macOS Keychain items `Claude Code-credentials` / `com.steipete.codexbar.cache`, or `~/.claude/.credentials.json`) and polls `https://claude.ai/api/organizations/<org_id>/usage` (without following redirects). If `~/.kimi-code/credentials/kimi-code.json` exists, it also polls `https://api.kimi.com/coding/v1/usages`.
4. **Public Model & Pricing Docs Refresh & Version Checks:**
   * [`_engine_maintenance_loop()`](../server.py#L42707-L42712) fetches public markdown docs from `platform.claude.com` and `developers.openai.com` ([`server.py`](../server.py#L8434-L8452)) to update local token pricing tables.
   * [`_version_check()`](../server.py#L17627-L17672) checks `https://api.github.com/repos/amirfish1/claude-command-center/releases/latest`. Managed installs (`~/.ccc/claude-command-center`) also run `git fetch origin --tags` hourly ([`_start_auto_update_thread()`](../server.py#L18125-L18139); disable with `CCC_AUTO_UPDATE=0`).
5. **Browser CDN Assets:**
   * Opening the UI fetches Google Fonts (`fonts.googleapis.com` in [`static/index.html`](../static/index.html#L7-L9)) and Mermaid.js (`cdn.jsdelivr.net` in [`static/app.js`](../static/app.js#L13994)).

### Outbound Data Flows That Are **Strictly Opt-In / User-Triggered**

* **AI Agent Sessions:** Spawning or messaging Claude, Codex, Gemini, Kimi, or Devin sends prompts and repo context to those providers via their CLIs.
* **CCC Cloud Relay:** [`ccc_server/cloud_relay.py`](../ccc_server/cloud_relay.py#L31-L55) is disabled unless explicitly paired; when paired, it pushes redacted session state every 20s to your relay URL.
* **TypeSafe Jev Repo Guess:** [`ccc_server/repo_guess.py`](../ccc_server/repo_guess.py#L607-L625) only runs if you configure a `JEV_API_KEY` (sends scrubbed prompt + repo labels/session titles to `https://api.typesafe.ai/v1/systemone`).
* **Share Cards & Bug Reports:** Clicking Share on the throughput page uploads a PNG card to `https://ccc-card.claude-command-center.workers.dev` ([`static/throughput.html`](../static/throughput.html#L847)), and submitting a bug report posts via `gh issue create` or to `https://support.claude-command-center.workers.dev/v1/report` ([`server.py`](../server.py#L18155)).

---

## 3. Are Any System Files or Permissions Modified?

**Short answer:** **No OS/root system files (`/etc`, `/System`, `/Library`, `/usr`) are modified, and `sudo` is never used.** However, running `./run.sh` modifies several **user-level** directories, Python user packages, and background services in `$HOME`.

### What `./run.sh` Modifies Automatically (Even Without `--install-service`)

1. **Symlinks `~/.local/bin/ccc` & `chmod +x`:**
   * [`run.sh`](../run.sh#L850-L855) calls [`scripts/link-ccc-cli.sh`](../scripts/link-ccc-cli.sh#L39-L46), which runs `chmod +x` on the repo’s [`ccc`](../ccc) script and creates/updates the symlink `~/.local/bin/ccc`.
2. **Installs WatchTower into Python User Site-Packages & Starts a LaunchAgent:**
   * Unless `CCC_SKIP_WATCHTOWER=1` is set, [`run.sh`](../run.sh#L816-L842) runs [`scripts/install-watchtower.sh`](../scripts/install-watchtower.sh#L353-L408), which installs `watchtower` into your user Python environment (`pip install --user` or a `.pth` file in user site-packages) and runs `wt start` (unless `CCC_SKIP_WATCHTOWER_DAEMON=1`), which installs and loads `~/Library/LaunchAgents/ai.watchtower.watcher.plist`.
3. **Spawns a Detached `ccc_worker.py` Daemon:**
   * Unless `CCC_CONTROL_PLANE_ENGINES=0` is set, [`run.sh`](../run.sh#L871-L949) launches `nohup python3 ccc_worker.py` in the background, which stays running after you `Ctrl+C` the foreground server.
4. **Syncs Internal Hook Copies & Session Registration:**
   * [`_sync_hook_scripts()`](../server.py#L42512) copies `hooks/*.py` into `~/.claude/command-center/hooks/` (and updates already-installed copies in `~/.claude/hooks/` if present), and [`_ccc_peer_server_start()`](../server.py#L42650) writes `~/.claude/sessions/<pid>.json`.

### What Requires Explicit User Consent or Flags

* **Modifying `~/.claude/settings.json`, `~/.codex/hooks.json`, and `~/.claude/skills/`:**
  * Gated behind the **Consent Gate** ([`ccc_server/config_consent.py`](../ccc_server/config_consent.py#L22-L135)). CCC will not wire hooks into your Claude/Codex config files or install skills until you approve them in the UI modal or via `ccc consent` (and it saves timestamped backups in `~/.claude/command-center/config-backups/`).
* **Installing CCC Login Services (`./run.sh --install-service`):**
  * Only when passed `--install-service` (or chosen interactively in [`scripts/install.sh`](../scripts/install.sh)), [`run.sh`](../run.sh#L33-L52) writes and loads `~/Library/LaunchAgents/com.github.claude-command-center.plist`, `com.github.claude-command-center.worker.plist`, and (if `kimi` is installed) `com.github.claude-command-center.kimi-web.plist` on macOS (or `~/.config/systemd/user/ccc*.service` on Linux).
* **File Permissions (`chmod` / `umask`):**
  * Only affects CCC's own files in `$HOME` (`0600` for secret/credential/socket files, `0700` for secret/config directories, and `0755` for its own hook/CLI scripts) plus raising its own process open-file soft limit (`RLIMIT_NOFILE`) in [`_raise_open_file_limit()`](../server.py#L42488).

---

## Running Locally with Maximum Isolation

To run CCC directly without installing WatchTower, without spawning the detached worker, and with telemetry and auto-updates disabled, launch `server.py` directly:

```bash
CCC_TELEMETRY_DISABLED=1 \
CCC_SKIP_WATCHTOWER=1 \
CCC_SKIP_WATCHTOWER_DAEMON=1 \
CCC_AUTO_UPDATE=0 \
CCC_CONTROL_PLANE_ENGINES=0 \
python3 server.py
```
