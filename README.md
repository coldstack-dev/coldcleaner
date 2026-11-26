# coldcleaner

Coldcleaner removes finished Git worktrees published on GitHub and archives listed scratch, evidence and temp folders, verifying copies before deletion. It cleans locally or over SSH (Linux, macOS and Windows).

> **What it never touches**
>
> - Anything you did not list in your rules file. The report lists the largest folders directly under home or `roots`, but never touches them.
> - Anything a scheduled job uses (cron, systemd, launchd or Windows Task Scheduler).
> - Any file a running program has open, any folder holding one, and any worktree a coding agent is still using.
> - Any folder with a `.keep-local` file in it or above it.
> - System, personal and cloud-drive folders, Obsidian vaults and a host's `protected` list ([list](docs/reference.md#protections-in-detail)).
> - Git work that is not on GitHub: uncommitted files, stashes, unpushed commits and open pull requests.
> - Anything changed recently: 4 days for archived folders, 7 days for worktrees (1 day once merged).
> - GitHub itself (no force-push, no new repositories), virtual machines, containers and Docker volumes.
> - Package caches. The archive tier skips well-known cache folders (`.cache`, `.npm`, `.cargo`, `.bun`, `npm-cache`, `pip-cache`, `uv-cache`, `go-build`, `node-compile-cache`) and the trees that contain them. Only explicitly supported agent cache files can be archived from inside `~/.cache`.
>
> By default nothing is changed at all. It only deletes when you pass `--apply` **and** list that kind of cleanup in `live` in your rules file. The example rules list nothing.

## Install

Coldcleaner needs Python 3.14. The simplest install uses [uv](https://docs.astral.sh/uv/), which downloads Python 3.14 for you if needed. If you don't have uv yet:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then open a new terminal so the `uv` command is found.

Cleanup itself also needs `tar`, `zstd`, `git`, `lsof` and the GitHub CLI `gh` (logged in with `gh auth login`). A dry run works without them. `coldcleaner doctor` checks for `zstd`, `git` and `gh`.

Other ways to install (pipx, pip in a virtual environment, or running from the checkout) are in [docs/reference.md](docs/reference.md#other-ways-to-install).

## Quick start (one machine)

```sh
uv tool install git+https://github.com/TayHCode/coldcleaner@v0.3.2
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
[ -e "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml" ] || { curl -fsSL https://raw.githubusercontent.com/TayHCode/coldcleaner/v0.3.2/rules.example.toml -o "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml.part" && mv "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml.part" "${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner/rules.toml"; }
coldcleaner doctor
coldcleaner reclaim --host local
```

1. `uv tool install` adds the v0.3.2 command to `~/.local/bin`. To install from a clone, run `uv tool install .`.
2. Download the example to `~/.config/coldcleaner/rules.toml` or `$XDG_CONFIG_HOME/coldcleaner/rules.toml`. An existing file is kept.
3. `doctor` reports PASS or FAIL for each prerequisite. Add `--json` for structured check results. Exit 1 means a check failed. You can still dry-run.
4. `reclaim --host local` writes a dry-run report with proposed actions and skip reasons. It prints the report path, disk use and estimated savings.

The example rules list no folders.

## Host-local policy

Before enabling cleanup, create `~/.config/coldcleaner/local.json` on each host. It allows worktrees under `roots` and folders matching `archive` globs. Without it, the host keeps every candidate.

```json
{"roots": ["~/projects"], "archive": ["~/projects/*/.scratch"]}
```

## Sudo

Coldcleaner checks running processes before removal. On Linux and macOS, non-root users need passwordless `sudo -n` for this inventory. If sudo fails, coldcleaner skips candidates with `IN USE: process inventory needs passwordless sudo (see README#sudo)`. If an unprivileged container reports `process inventory incomplete: /proc not readable`, run coldcleaner on the container's host.

On Linux, install the read-only scan from the repository folder. Repeat this after every upgrade.

```sh
python3 -c 'import coldcleaner.reclaim_probe as p; print(p.PROC_SCAN, end="")' | sudo install -D -m 0644 /dev/stdin /usr/local/libexec/coldcleaner-proc-scan.py
```

This needs `python3` to be Python 3.14. If your Python 3.14 came from uv, start the line with `"$(uv tool dir)/coldcleaner/bin/python" -c` instead of `python3 -c`. For a remote host, pipe into `ssh HOST 'sudo install -D -m 0644 /dev/stdin /usr/local/libexec/coldcleaner-proc-scan.py'` instead.

Then add this rule with `sudo visudo -f /etc/sudoers.d/coldcleaner`. Replace `alice` with the user that runs coldcleaner (the SSH user, for a remote host), and `/usr/bin/python3` with the output of `command -v python3` on that host:

```text
alice ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/coldcleaner-proc-scan.py /proc
```

On macOS, the check runs `lsof` and `ps`:

```text
alice ALL=(root) NOPASSWD: /usr/sbin/lsof -nP -Fn, /bin/ps -axww -o command\=
```

## Turn cleanup on

`coldcleaner init` asks six policy questions and backs up edited rules. Blank answers retain settings; `coldcleaner init --yes` keeps current settings without prompting. It selects no new paths.

Open the rules file you copied during quick start.

1. Under `[hosts.local]`, set `roots` to the folders that hold your Git repositories, for example `roots = ["~/projects"]`. Coldcleaner finds worktrees inside them.
2. Set `archive` to the scratch or temp folders you want archived and removed once they are idle, for example `archive = ["~/projects/*/.scratch"]`.
3. Set `nas_root` to the folder where archives go. The name comes from NAS (network-attached storage): the folder must be on a network share (NFS or SMB), or on a second drive that you name in `local_archive_mount`. See [Archive storage](docs/reference.md#archive-storage).
4. Set a live tier, for example `live = ["archive"]`. Run `coldcleaner check-rules` and `coldcleaner doctor --host local`. Both accept `--json` for structured results. Resolve any failures, then run `coldcleaner reclaim --host local` to write a fresh dry-run report.
5. Open the report at the path printed by `reclaim`. Pick a candidate and check its path, proposed action or skip reason, and whether the disposition matches your intent. Review the other proposed actions too. If anything looks wrong, correct the setup and rerun the dry run.
6. Run `coldcleaner reclaim --host local --apply --i-reviewed REPORT`, replacing `REPORT` with the path to the dry-run report you reviewed. Confirm `Mode: apply` and check the result before scheduling cleanup.

`--apply` requires a live tier and a current-rules dry run per host. Worktree cleanup uses `gh` to verify published commits and pull requests.

There are two kinds of cleanup:

| `live` entry | What it removes | When |
| --- | --- | --- |
| `worktree` | Git worktrees under `roots` (`git worktree remove`, then the local branch) | The worktree's commits are on GitHub, its branch is merged or its pull request is closed, and it has been idle 7 days (1 day once merged). Ignored files inside are archived first. |
| `archive` | Folders listed in `archive` | Idle 4 days (system temp folders 7 days). Each is archived to `nas_root`, every file's SHA-256 checksum is compared with the original, and only then is it deleted. |

Get anything back with `coldcleaner find TERM` (search archives by path) and `coldcleaner restore ID`, which never overwrites an existing path.

## Run it every night

Once a live run looks right, schedule `coldcleaner reclaim --apply` daily with a systemd user timer on Linux or cron on macOS. Copy-paste setups for both are in [docs/reference.md](docs/reference.md#run-it-every-night).

After a rules change, the nightly records a dry run for each uncovered host. The next nightly can apply automatically using that report.

In text mode, exit code 0 means the run completed, including when `--apply` recorded a dry run. Exit code 1 means a step failed or an SSH outage left the scan without a completed host. Exit code 2 means the command refused to run, for example because of bad rules or arguments. Exit code 3 means a host needs attention for an isolated SSH outage, missing apply coverage, disk use at or above `alert_pct` (80% in the example), or at least 1 GiB skipped due to the per-run deletion limit.

With `--json`, `reclaim`, `doctor` and `check-rules` return one versioned result. Exit 0 means success, 1 means a finding or refusal, and 2 means a usage or runtime error. See the [JSON schema](docs/reference.md#calling-it-from-another-tool).

## More

[docs/reference.md](docs/reference.md) has the details:

- every command and option, including `status`, `find TERM` and `restore ID`;
- remote hosts over SSH, Windows and WSL;
- archiving to a local drive instead of a NAS;
- what the report shows, the actions log, and JSON output for other tools;
- every protection, in detail;
- known limitations.

`coldcleaner --help` lists the commands, and `--help` after any command describes it. Every command accepts `--rules PATH` to use another rules file, and `--host NAME` picks one host where it applies. `coldcleaner --version` prints the version.

## Limitations

When any safety check fails or cannot run, coldcleaner keeps the item, so it often leaves behind things you expected it to remove. Projects with nested repositories need manual review. The tests use fake hosts and do not prove correctness on every remote system, so check a dry run of every new configuration before `--apply`. The full list is in [docs/reference.md](docs/reference.md#limitations).

## Development

Install Python 3.14, Git, tar and zstd, then run the offline tests from the repository folder:

```sh
python3 -m unittest discover -s tests -v
```

Tests use temporary folders, local Git remotes and fake hosts, without network access. See `CONTRIBUTING.md`, `SECURITY.md` and the MIT `LICENSE`.

Preservation defaults stay enabled. See [cleanup policy options](docs/reference.md#cleanup-policy-options) to disable archiving, copy verification, vault receipts or the wait period.
