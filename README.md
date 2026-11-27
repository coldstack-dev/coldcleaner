# coldcleaner

Coldcleaner removes finished Git worktrees published on GitHub and archives listed scratch, evidence and temp folders, verifying copies before deletion. It cleans locally or over SSH (Linux, macOS and Windows).

> **What it never touches**
>
> - Anything you did not list in your rules file. The report lists the largest folders under home or `roots`, report only.
> - Anything a scheduled job uses (cron, systemd, launchd or Windows Task Scheduler).
> - Any file a running program has open, any folder holding one, and any worktree a coding agent is using.
> - Any folder with a `.keep-local` file in it or above it.
> - System, personal and cloud-drive folders, Obsidian vaults and a host's `protected` list ([list](docs/reference.md#protections-in-detail)).
> - Git work that is not on GitHub: uncommitted files, stashes, unpushed commits and open pull requests.
> - Anything changed recently: 4 days for archived folders, 7 days for worktrees (1 day once merged).
> - GitHub itself (no force-push, no new repositories), virtual machines, containers and Docker volumes.
> - Package caches (`.cache`, `.npm`, `.cargo`, `.bun`, `npm-cache`, `pip-cache`, `uv-cache`, `go-build`, `node-compile-cache`). Only explicitly supported agent cache files can be archived from `~/.cache`.
>
> By default nothing is changed at all. It only deletes when you pass `--apply` **and** list that tier in `live` in your rules file. The example rules list nothing.

## Install

Coldcleaner needs Python 3.14; [uv](https://docs.astral.sh/uv/) downloads it automatically. Install uv if needed, then open a new terminal:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Cleanup also needs `tar`, `zstd`, `git`, `lsof` and the GitHub CLI `gh` (`gh auth login`). A dry run works without them; `coldcleaner doctor` checks `zstd`, `git` and `gh`. Other install methods (pipx, virtual environments, or running from source) are in [docs/reference.md](docs/reference.md#other-ways-to-install).

No telemetry. Network: optional `gh` checks (auth status, PRs, branches) and `git ls-remote` to GitHub, plus SSH to any remote host configured with `ssh` (including `--host`, `--to-host`, `reclaim_hosts`, and `collect_hosts`).

## Quick start (one machine)

```sh
uv tool install git+https://github.com/coldstack-dev/coldcleaner@v0.3.3
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
[ -e "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml" ] || { curl -fsSL https://raw.githubusercontent.com/coldstack-dev/coldcleaner/v0.3.3/rules.example.toml -o "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml.part" && mv "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml.part" "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml"; }
coldcleaner doctor
coldcleaner reclaim --host local
```

1. `uv tool install` adds the v0.3.3 command to `~/.local/bin` (from a clone, run `uv tool install .`).
2. Download the example to `~/.config/coldcleaner/rules.toml` (or `$XDG_CONFIG_HOME/coldcleaner/rules.toml`). Existing files are kept.
3. `doctor` reports PASS or FAIL per prerequisite (add `--json` for structured output). Exit 1 means a check failed; dry runs still work.
4. `reclaim --host local` writes a dry-run report with proposed actions, skip reasons, disk use and estimated savings.

## Try it on a throwaway folder

The example rules list no folders, so the first dry run shows `would free 0.00 GiB`. To see a non-zero plan without touching real data, create a unique temporary folder and dry-run a rules copy against it:

```sh
DEMO="$(mktemp -d "$HOME/coldcleaner-demo.XXXXXX")"
mkdir -p "$DEMO/items/old" && dd if=/dev/zero of="$DEMO/items/old/sample.bin" bs=1048576 count=10 2>/dev/null
touch -t 202001010000 "$DEMO/items/old/sample.bin" "$DEMO/items/old"
sed "s|^archive = \[\]|archive = [\"$DEMO/items/*\"]|" "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml" > "$DEMO/rules.toml"
coldcleaner reclaim --host local --rules "$DEMO/rules.toml"
```

Open the printed report to see `$DEMO/items/old` proposed as `would archive and remove` (configure [Sudo](#sudo) first if process checks skip it). Nothing is deleted; clean up with `rm -rf "$DEMO"`.

## Host-local policy

Before enabling cleanup, create `~/.config/coldcleaner/local.json` on each host. It allows worktrees under `roots` and folders matching `archive` globs; without it, every candidate is kept.

```json
{"roots": ["~/projects"], "archive": ["~/projects/*/.scratch"]}
```

## Sudo

Coldcleaner checks running processes before removal. On Linux and macOS, non-root users need passwordless `sudo -n` for this inventory; otherwise candidates are skipped with `IN USE: process inventory needs passwordless sudo (see README#sudo)`. If an unprivileged container reports `process inventory incomplete: /proc not readable`, run coldcleaner on the container's host.

On Linux, install the read-only scan from the repository folder (repeat after upgrades):

```sh
python3 -c 'import coldcleaner.reclaim_probe as p; print(p.PROC_SCAN, end="")' | sudo install -D -m 0644 /dev/stdin /usr/local/libexec/coldcleaner-proc-scan.py
```

This needs Python 3.14; with uv, replace `python3 -c` with `"$(uv tool dir)/coldcleaner/bin/python" -c`. For remote hosts, pipe into `ssh HOST 'sudo install -D -m 0644 /dev/stdin /usr/local/libexec/coldcleaner-proc-scan.py'`.

Add this rule with `sudo visudo -f /etc/sudoers.d/coldcleaner`, replacing `alice` with the user and `/usr/bin/python3` with `command -v python3` on that host:

```text
alice ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/coldcleaner-proc-scan.py /proc
```

On macOS, the check runs `lsof` and `ps`:

```text
alice ALL=(root) NOPASSWD: /usr/sbin/lsof -nP -Fn, /bin/ps -axww -o command\=
```

## Turn cleanup on

`coldcleaner init` asks six policy questions and backs up edited rules (`coldcleaner init --yes` keeps current settings without prompting and selects no new paths).

Open your rules file:

1. Under `[hosts.local]`, set `roots` to folders holding Git repositories, e.g. `roots = ["~/projects"]`.
2. Set `archive` to scratch or temp folders to archive once idle, e.g. `archive = ["~/projects/*/.scratch"]`.
3. Set `nas_root` to the archive folder on a NAS (network-attached storage) or a second drive named in `local_archive_mount` ([Archive storage](docs/reference.md#archive-storage)).
4. Set a live tier, e.g. `live = ["archive"]`. Run `coldcleaner check-rules` and `coldcleaner doctor --host local` (both accept `--json`). Resolve failures, then run `coldcleaner reclaim --host local`.
5. Review the printed dry-run report to verify proposed actions and skip reasons.
6. Run `coldcleaner reclaim --host local --apply --i-reviewed REPORT` with that report path. Confirm `Mode: apply` before scheduling.

`--apply` requires a live tier and a current-rules dry run per host. Worktree cleanup uses `gh` to verify published commits and pull requests.

| `live` entry | What it removes | When |
| --- | --- | --- |
| `worktree` | Git worktrees under `roots` (`git worktree remove`, then the local branch) | Commits are on GitHub, branch is merged or PR closed, idle 7 days (1 day once merged). Ignored files are archived first. |
| `archive` | Folders listed in `archive` | Idle 4 days (system temp 7 days). Archived to `nas_root` and every file's SHA-256 verified before deletion. |

Recover archives with `coldcleaner find TERM` and `coldcleaner restore ID` (never overwrites existing paths).

## Run it every night

Once a live run looks right, schedule `coldcleaner reclaim --apply` daily with systemd on Linux or cron on macOS ([docs/reference.md](docs/reference.md#run-it-every-night)). After a rules change, the nightly records a dry run for uncovered hosts so the next run can apply.

Text-mode exit codes: `0` completed (including automatic dry runs), `1` failure or full SSH outage, `2` refused (bad rules or arguments), `3` attention needed (isolated SSH outage, missing apply coverage, disk `>= alert_pct`, or `>= 1 GiB` skipped by deletion limits).

With `--json`, `reclaim`, `doctor`, `check-rules` and `reflink` return versioned JSON (`0` ok, `1` finding/refusal, `2` error; [JSON schema](docs/reference.md#calling-it-from-another-tool)).

`coldcleaner reflink` deduplicates identical clean files across active Git worktrees in-place with Linux `FIDEDUPERANGE` (Btrfs/XFS). macOS APFS reports duplicates in dry-run only (`--apply` is an `unsupported` no-op); other filesystems return `unsupported`. Dry-run by default; add `--apply` and `--json`.

## More

[docs/reference.md](docs/reference.md) covers every command (`reflink`, `status`, `find TERM`, `restore ID`), remote hosts over SSH/Windows/WSL, local-drive archiving, JSON output, protections and [cleanup policy options](docs/reference.md#cleanup-policy-options). Every command accepts `--rules PATH`, `--host NAME` selects one host, `--help` describes options, and `coldcleaner --version` prints the version.

## Limitations

When any safety check fails, coldcleaner keeps the item. Projects with nested repositories need manual review. Tests use fake hosts, so dry-run every new configuration before `--apply` ([docs/reference.md](docs/reference.md#limitations)).

## Development

Install Python 3.14, Git, tar and zstd, then run offline tests from the repository:

```sh
python3 -m unittest discover -s tests -v
```

Tests use temp folders, local Git remotes and fake hosts without network access. See `CONTRIBUTING.md`, `SECURITY.md` and `LICENSE`.
