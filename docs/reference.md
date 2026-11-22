# coldcleaner reference

The [README](../README.md) covers installing, the one-machine quick start and turning cleanup on. This page has the details.

## Other ways to install

`pipx install .` works when Python 3.14 is installed. Inside an active Python 3.14 virtual environment, pip installs it too:

```sh
python3 -m pip install .
```

With Python 3.14 as `python3`, you can also run it from the repository folder without installing:

```sh
python3 -m coldcleaner --help
```

Under an older Python it exits 2 with `coldcleaner needs Python 3.14+ (found 3.12)` before doing anything. `python3 -m coldcleaner --version` prints the version from `pyproject.toml` (an installed copy prints its package version). Releases are tagged `v<version>`. Coldcleaner uses only Python's standard library.

## The rules file

An installed copy reads `~/.config/coldcleaner/rules.toml` (or `$XDG_CONFIG_HOME/coldcleaner/rules.toml`). Running from a repository folder that has its own `rules.toml` uses that file. Every command accepts `--rules PATH` to read another file.

The example writes reports to `~/.local/state/coldcleaner/reports` and sets `nas_root` to `~/.local/share/coldcleaner/archive`, so a dry run works as any user. Archiving refuses until `nas_root` is on network storage or under `local_archive_mount` ([Archive storage](#archive-storage)), and `reclaim --apply` exits 2 without touching any host while `nas_root` does not exist. The example has one local host, `live = []`, and no cleanup paths.

### Hosts

Each `[hosts.<name>]` table needs `kind` (`posix`, `powershell` or `wsl`) and accepts `ssh` (an SSH destination) and `distro`. A `posix` host without `ssh` runs on a POSIX controller. A `powershell` host without `ssh` runs on a Windows controller. Other hosts need `ssh`. `reclaim --host HOST --local` and `doctor --host HOST --local` require the selected host kind to match the controller. The example file has commented remote POSIX and Windows hosts. `reclaim_hosts` lists the hosts that `reclaim` cleans by default; without it, every configured host except WSL.

Rules files written before hosts moved into configuration are refused until every host table declares `kind`. Add `ssh = "<destination>"` to each remote host, because a table without `ssh` runs on this machine.

Remote macOS hosts need Bash 3.2 and Python 3.9 or newer. Native Windows uses PowerShell. Compression always happens on the controller.

Use `collect_hosts` for remote POSIX hosts that write separate local reports. Each host needs `ssh` and a host-local `report_dir`. Adding a host to `collect_hosts` removes it from the default reclaim targets, even when `reclaim_hosts` still lists it.

After the default `reclaim --apply` scan, the controller reads each host's newest local report over SSH and stores a copy under `fleet/collected/<host>/` in the controller report directory. `fleet/summary.md` names the latest copies and includes the apply reports. The controller imports only action fields printed in the report. If collection fails, the controller keeps the last copy, records the failure in the run report, and exits 1.

A host can list `shared_roots` for shared disk folders such as `/srv/shared`. A scheduler reference to that folder protects the folder itself; references to its children still protect those children.

## What reclaim removes

`coldcleaner reclaim` cleans the `reclaim_hosts` (or one `--host`). `--host H --local` runs host H on this machine without SSH, as each Linux host's own `coldcleaner-local` timer does; H must be a `posix` host and gets the same output-path checks as a host without `ssh`. It is a dry run unless you add `--apply`, and `--apply` acts only on tiers listed in `live`. Each report records `Rules: sha256 <hash>` of the rules file bytes. A `reclaim` dry run also writes `Reclaim dry run complete for: <hosts>`, naming each host that ran without errors. Each host can apply only after its dry run completes with the current rules hash. Reports in `report_dir` (or `--report-dir`) add up. If no selected hosts have a matching report, `--apply` runs and records a dry run for all of them. With partial coverage it applies the covered hosts and dry-runs the rest. Reports from the removed `run` command and failed hosts never count. `--i-reviewed REPORT` requires that one report to cover every selected host and match the current rules hash, or exits 2. WSL and package caches are out of scope. A rules file with a `cache` or `cache_tools` table, `cache_idle_days` or `cache` in `live` is rejected with `removed; caches are out of scope`.

**Worktrees** (`worktree` tier). Git worktrees under the host's `roots`. A worktree is removed only after a fresh check against GitHub shows that its current head is published and either merged or the head of a closed pull request. A merged worktree must be idle 1 day (or `worktree_idle_days`, if lower); one whose pull request was closed without merging must be idle `worktree_idle_days` (7 in the example). Coldcleaner runs `git worktree remove` and deletes the local branch, unless the worktree is detached or another worktree has that branch checked out. Ignored files inside are archived first, with a Git recovery bundle, so a full restore recreates a usable repository. A worktree held only for uncommitted, unpushed or unmerged work (no stash and no open pull request) that has been idle `abandoned_idle_days` (default 30) is listed as an approval-gated plan item. Once approved, its whole tree and a recovery bundle of HEAD and its reflog are archived and verified, the worktree is removed, and the local branch is kept; `restore ID` brings back the dirty files. Stated limit: the checkout is hashed and its Git state rechecked after it is renamed aside, then a last process scan runs before deletion. A process that writes into the renamed folder and exits during that scan, or a stash created elsewhere in the repository during it, is not seen; new file bytes from that write are deleted without an archived copy (a new stash survives). This needs a writer that starts after 30 idle days, finds the hidden renamed folder and exits within one scan.

**Archive folders** (`archive` tier). Paths and glob patterns listed under the host's `archive`, once idle `archive_idle_days` (4 in the example). System temp folders (`/tmp`, `/var/tmp`, Windows `AppData\Local\Temp` and `Windows\Temp`) need at least 7 idle days. Each is archived, every file's SHA-256 checksum is compared with the original, and only then is the source deleted. An entry may be a table, `{ path = "...", days = 30, backup = "nas", exclude = ["..."] }`: `days` replaces `archive_idle_days` for that pattern (the 7-day temp minimum still applies). `exclude`, and the host's own `exclude` list, drop any match that equals, sits inside or holds an excluded path. `backup` is `nas` (the default) or `none-if-regenerable`, which needs a path ending in `node_modules`, `.venv`, `venv`, `target`, `dist`, `build`, `__pycache__`, `.cache` or `.next`. Both values still archive and verify the copy before deletion. `category` tags the pattern for the report's totals: `scratch` (the default, also for plain string entries), `test-output` or `artifact`. When several patterns match the same path, the first tagged one wins over untagged ones; a pattern that only matches a folder's contents does not tag the folder. An `artifact` path, such as an agent transcript, is held unless the top-level `memory_store` folder (ColdVault first) holds its preservation receipt: `<memory_store>/<sha256 of "HOST:PATH">.json`, with the six Coldvault v2 fields `schema_version`, `host`, `path`, `sha256`, `destination` and `verified_at`. The UTC timestamp uses `YYYY-MM-DDTHH:MM:SSZ`. On the source host, the absolute destination must be an independent regular file outside the cleanup target. Preview checks both files. Removal rechecks the receipt and verifies the current original and destination against the receipt digest. Legacy digest receipts and summary-only receipts hold the original, including under `preservation = "summary"`. Without `memory_store`, artifact paths are never removed. No `archive` or `roots` rule may cover `memory_store`.

The legacy `run` and `github` commands, the `project`, `compact` and `github` tiers and the archive storage cap are removed. A rules file that still sets `hard_pct`, `project_idle_days`, `compact_idle_days`, `compact_weekday`, `nas_cap_gb`, `regenerable_paths`, a host `compact` list or one of those tiers in `live` is rejected with `removed with the legacy run tiers; delete <keys>`, naming each key.

## Protections in detail

Reclaim keeps a candidate when any of these is true. An incomplete check also keeps it.

- **Git work not on GitHub.** Dirty files, unpushed commits, open pull requests, and published heads that are neither merged nor the head of a closed pull request. A stash holds the main checkout only; removing a linked worktree preserves the repository's shared stash. Coldcleaner never force-pushes and never creates GitHub repositories.
- **Schedulers.** Paths named by systemd units and timers, crontab, launchd or Task Scheduler. A Task Scheduler action that names a WSL path `/mnt/<drive>/...` protects the matching `<DRIVE>:\...` path. Broad references such as your home folder, `/` or `C:\` protect only that exact path. A system unit link whose target no longer exists is skipped when systemd reports that unit as not loaded (`LoadState=not-found`), since it schedules nothing; any other unreadable scheduler file makes the check incomplete.
- **Running programs.** Files open in a running program, and their parent folders, and the working folders and command lines of running programs. Each live batch takes a fresh snapshot. On Linux and macOS this needs root or passwordless sudo ([README](../README.md#sudo)).
- **Coding agents.** Worktrees in use by T3 Code (a desktop app that runs coding agents), the Codex CLI or Claude Code. Coldcleaner reads each agent's local state: T3 Code's `~/.t3/userdata/statev2.sqlite`, Codex's newest `~/.codex/state_N.sqlite` and every `cwd` in Claude Code's `~/.claude/projects/**/*.jsonl` session files. Active T3 runs, pinned or unsettled T3 threads, unarchived Codex threads updated within the tier's idle days, and Claude Code sessions whose file changed within the tier's idle days keep their worktrees. An absent agent is noted once per host (`T3 not installed`). If that state cannot be read, for example after an agent upgrade changes it, every candidate on the host is kept with one `IN USE: <agent> state unreadable` reason. Codex and Claude Code sessions whose folder is the home folder or `/` protect only that folder. Any session whose folder is the home folder, a host `roots` entry or a `shared_roots` entry still protects that folder and every folder holding it, but not what is inside it.
- **`.keep-local`.** Any folder with a `.keep-local` file in it or above it.
- **`.coldcleaner-lease`.** Any agent can claim a folder until a time: write one UTC time such as `2026-12-01T00:00:00Z` to `.coldcleaner-lease` in the folder. Until then, that folder, everything inside it and any candidate containing it are kept. An expired lease is ignored; a lease that cannot be read or parsed protects like an unexpired one.
- **Artifact markers.** A Cold Stack artifact marker (`.cold-artifact.json` inside a folder, `<file>.cold-artifact.json` beside a file) in, above or inside a candidate keeps it while its `retention.policy` is `keep` or its `temporary` `expires` time is still ahead. A marker that is not a regular file, cannot be read or breaks the schema (`schema_version` 1) also keeps it. An expired `temporary` marker still keeps it while its `owner` is running: a process with a command-line word whose last path part, before its first dot, equals the owner (case-insensitive: `coldcontribute`, `/opt/coldcontribute.py` and `-m coldcontribute.fix` all count), or a process list that cannot be read (including a Linux `/proc` mounted with `hidepid` when the probe is not root; macOS reads it through `sudo`). Windows protected system processes, whose command lines no one can read, are not checked; they are operating-system processes, not products. On a Windows host the processes of every running WSL distro (WSL 1 or 2) are listed too, as root; if no distro is listed or a list cannot be read, the artifact is kept, so a Windows host without a running distro keeps expired artifacts. This can over-hold: any process whose arguments contain the owner's name, such as an editor or shell in a folder named after it, keeps that owner's expired artifacts for that run. Once a `temporary` marker expires and its owner is not running, the owner has abandoned the artifact, and the tier's own rules apply: ColdContribute's receipts on ops (`~/.local/state/coldcontribute/fix/OWNER/REPO/ISSUE`) are then archived, verified and deleted like any archive folder once idle 30 days; an unmarked receipt waits the same 30 idle days.
- **Protected locations.** Rules that overlap one fail to load. On the host, the check refuses any candidate that is inside, equal to or holding one: `/etc`, `/usr`, `/System`, `/mnt/shared-memory`, `C:\Windows` (its `Temp` stays allowed), `Program Files*`, the home folder's `Documents`, `Desktop`, `Pictures`, `Library`, `iCloud Drive`/`iCloudDrive`, `Google Drive` and `OneDrive*`, any folder holding `.obsidian`, and the paths in the host's `protected` list (no globs). The host check also covers glob expansions that the rules check cannot see.
- **Recent changes.** Anything changed within its idle window.
- **File system details.** Mount points and nested file systems. Windows files with alternate data streams. POSIX ACLs, extended attributes, special modes and files owned by other users (the macOS `com.apple.provenance` and `com.apple.quarantine` stamps hold no user data and are the only attributes allowed).
- **Never in scope.** Remote branches, GitHub repositories, registered VM disks, containers, Docker volumes and services other than coldcleaner's own timer. Reclaim never expires archives.

Archive copies keep Windows owner, group and DACL descriptors, and POSIX ownership, modes and timestamps. Checks run again just before removal; they do not lock paths against programs that start writing afterwards.

### Windows and WSL

Native Windows reclaim needs every running program's command line. An unreadable command line blocks cleanup. Only the probe itself, kernel processes with PIDs 0 and 4, and processes that Windows reports as protected (for example `lsass.exe`, `Registry`, `LsaIso.exe` and Defender), whose command line and executable path are both unreadable, are left out.

While the WSL virtual machine runs, the Windows check reads the open files of every process inside each running WSL distro, as root and read-only, and maps drive mounts such as `/mnt/c` to Windows paths, so Windows data a WSL job uses stays protected. If that read fails, Windows reclaim is incomplete. The Windows Sandbox template VM counts only while no sandbox session runs. WSL is never stopped.

Running cleanup inside WSL is retired. Runs report its tiers as skipped and keep reporting disk pressure on `C:`. Old WSL archives can still be restored with `restore ID --to-host HOST --to PATH` on a POSIX host.

## Schedule Windows-local cleanup

Use a clone on the Windows machine and an administrator account with Python 3.14, Git and authenticated `gh`. Python supplies Zstandard compression on Windows. The task runs when that account is signed in, including while Windows is locked.

1. Copy the rules to a file outside the clone. Keep only that Windows host, use `kind = "powershell"`, omit `ssh` and give the host its Windows computer name. Keep the host-local cleanup allowlist at `~/.config/coldcleaner/local.json`.
2. Set `nas_root` to a dedicated SMB archive folder accessible to the task account, such as `'\\nas\coldcleaner\archive-windows'`. Give the Windows controller its own archive index and `report_dir`, such as `"~/.local/state/coldcleaner/reports"`. Use separate state from POSIX controllers because their file locks use a different protocol.
3. From the clone, run these commands in elevated PowerShell. Set `$rules` to your rules file and `$python` to the full path of the Python 3.14 executable.

   ```powershell
   & $python -m coldcleaner doctor --rules $rules --host ($env:COMPUTERNAME.ToLowerInvariant()) --local
   & .\windows\install.ps1 -Rules $rules -Python $python -DryRun
   Start-ScheduledTask -TaskName Coldcleaner
   Get-ScheduledTaskInfo -TaskName Coldcleaner
   ```

4. Wait for the task to finish and review the dry-run report. For gated items, run `& $python -m coldcleaner approve --rules $rules PLAN ID` using the plan and item IDs from that report.
5. Run `& .\windows\install.ps1 -Rules $rules -Python $python` to switch the same daily 04:30 UTC task to apply. Keep remote nightly runs off that host after cutover.

A successful dry run with the current rules is required before apply. With archiving enabled, apply requires access to the SMB archive folder.

For Windows worktree cleanup without SMB, set `live = ["worktree"]` and `archive_before_delete = "off"` in the Windows rules before the dry run. Windows holds worktrees with ignored files or unpublished reflog history under these rules. Set `approval = ["worktree"]` to require approval of individual worktrees.

## Archive storage

Archives go under `nas_root` as `<host>/<YYYY-MM-DD>/<name>.tar.zst`, with a `<name>.files.txt` list of every path and an `INDEX.csv` of all archives. The name comes from NAS (network-attached storage). By default the folder must be on an NFS or SMB network share.

A reclaim copy stays marked `attempt.creating`, and listed in `<nas_root>/.attempts/`, until its `INDEX.csv` row is written. The next copy to that `nas_root` deletes any listed, marked folder without a row. It reads only that list, not every archive folder. A retry whose source, permissions and Git head are unchanged reuses the indexed copy after a fresh test-read instead of copying again.

To archive to an external or second internal drive instead, mount it and name its mount point:

```toml
nas_root = "/mnt/backup/coldcleaner"
local_archive_mount = "/mnt/backup"
```

The same verification applies. `local_archive_mount` replaces the network-share check with these: the drive must be mounted at that exact path, the archive folder (after following symlinks) must be on it, it must be a different file system than `/`, it must not be memory-backed (`tmpfs`, `ramfs`), and it must not be the file system of the data being removed.

This mode only supports data on the controller. While it is set, archive candidates and worktrees with ignored data on any other host are left in place with an error in the report, because that host cannot recheck the drive before removal. Use a network share (leave `local_archive_mount` empty) for those hosts. The archive is checked again right before each removal, so an unplugged drive stops the run instead of filling an empty mount folder.

## Run it every night

For a POSIX host without shared storage, set these three keys in its existing `[hosts.<name>]` table:

```toml
report_dir = "~/.local/state/coldcleaner/reports"
archive_before_delete = "off"
live = ["worktree", "clone"]
```

`reclaim --host <name> --local` uses this policy and writes its own reports, plans, and action log. The dry-run guard requires a report from the same local policy. Worktrees and clones with ignored files or unpublished history stay in place. Clone removal still needs approval. Use `approve --report-dir ~/.local/state/coldcleaner/reports PLAN ID` to write it to the local report directory.

From a clean Git clone on branch `main`, run `scripts/deploy.sh local` on Linux or `scripts/install.sh local` on macOS. The packaged systemd timer runs at 04:30 UTC. The macOS LaunchAgent runs at 04:30 UTC while the Mac is awake and the installing user is signed in. It writes errors to `launchd.stderr.log` in the report directory. Both schedulers update their own checkout from `origin/main` before running. Install the host's existing `local.json` allowlist and run `python3 -m coldcleaner reclaim --host <name> --local` to produce the first dry-run report. The scheduler's hostname must match `<name>`.

Add the tiers you want to `live`, for example `live = ["worktree", "archive"]`. Run `coldcleaner reclaim` and review its dry-run report for the current rules before scheduling cleanup. Run the commands below from the shell you used for the quick start. `command -v coldcleaner gh` must print both paths: the scheduled run reuses that shell's `PATH`, the installed `coldcleaner` and your rules file.

On Linux, install a systemd user timer (04:30 local time):

```sh
config="${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/coldcleaner.service <<EOF
[Unit]
Description=coldcleaner nightly reclaim

[Service]
Type=oneshot
Environment="PATH=$PATH"
ExecStart="$(command -v coldcleaner)" reclaim --apply --rules "$config/rules.toml"
SuccessExitStatus=3
Nice=10
IOSchedulingClass=idle
EOF
cat > ~/.config/systemd/user/coldcleaner.timer <<EOF
[Unit]
Description=Nightly coldcleaner run

[Timer]
OnCalendar=*-*-* 04:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now coldcleaner.timer
loginctl enable-linger "$USER"
```

`loginctl enable-linger` lets the timer run while you are logged out. Check it with `systemctl --user list-timers coldcleaner.timer` and read a run with `journalctl --user -u coldcleaner.service`. `SuccessExitStatus=3` treats "worked, but a disk is still at or above `alert_pct`" as success, so `journalctl` shows a `coldcleaner: ATTENTION:` line instead of a failed unit. Add `OnFailure=<your-alert>.service` under `[Unit]` to be told about failures. To stop the nightly run: `systemctl --user disable --now coldcleaner.timer`.

For an installed CLI without a Git checkout, macOS and other hosts without systemd can use cron (04:30 local time):

```sh
config="${XDG_CONFIG_HOME:-$HOME/.config}/coldcleaner"
( crontab -l 2>/dev/null; echo "30 4 * * * PATH='$PATH' '$(command -v coldcleaner)' reclaim --apply --rules '$config/rules.toml'" ) | crontab -
```

## Commands

Every command accepts `--rules PATH`. `reclaim`, `status`, `doctor`, `metrics` and `approve PLAN ID` also accept `--report-dir PATH`; reports otherwise go to `report_dir` from the rules (`~/.local/state/coldcleaner/reports` in the example).

- `coldcleaner check-rules` validates the rules file without contacting hosts or scanning disks. Add `--json` for a versioned validation result. It exits 0 when the rules are valid, 1 when they are invalid (for example `missing required key alert_pct`) and 2 for usage or runtime errors, including an unreadable rules file.
- `coldcleaner doctor` prints one PASS or FAIL line per check: Python 3.14+, `zstd`, `git`, `gh auth status`, a writable `nas_root` and `report_dir` (or their nearest existing parent), and for each `reclaim_hosts` host (or `--host`) that it answers over SSH and that its process check, including passwordless sudo, works. Add `--json` for structured check results. It writes, moves and deletes nothing. It exits 0 when every check passes, 1 when a check fails, and 2 for usage or runtime errors. Invalid rules exit 1 with `--json` and 2 in text mode.
- `coldcleaner reclaim` previews or, with `--apply`, performs cleanup ([What reclaim removes](#what-reclaim-removes)). `--host` picks one host. `--json` prints one JSON summary ([Calling it from another tool](#calling-it-from-another-tool)). When `--apply` finds a current dry run for only some hosts, it applies those and dry-runs the rest; the summary then holds the dry run under `preview`.
- `coldcleaner status` shows disk use per host and the last report. A host at or above `alert_pct` gets a note on its line.
- `coldcleaner find TERM` searches archive records and file lists. It prints one line per archive with its restore ID, then matching members.
- `coldcleaner restore ID` puts an archive back where it came from. `--member M` restores one path from it, and `--to PATH` restores somewhere else. Restore refuses to overwrite an existing path and does not need `--apply`.
- `coldcleaner restore-drill` restores one random archive into a temporary folder under `~/.cache/coldcleaner/restore-drill` on this machine, checks every path against `.files.txt` and every file against the archive's SHA-256 receipt, deletes the copy and appends pass or fail to `restore-drill.jsonl` in the report folder. It does not change the archive or `INDEX.csv`, and exits 1 on a failure. `scripts/install.sh` schedules it weekly.
- `coldcleaner approve PLAN ID...` (or `approve PLAN all`) approves items from a dry-run plan ([Approval mode](#approval-mode)). It refuses IDs that are not in the plan and records nothing then.
- `coldcleaner metrics` prints one row per host for the last 7 days (`--days N` to change): bytes acted on, the `df` drop across `reclaim --apply` runs, distinct candidates, acted and held-for-a-person paths, the automation rate (acted ÷ (acted + held)), paths seen again after removal, restored archives (all time), the latest restore drill result from `restore-drill.jsonl` in the report folder, the disk-used trend and the age of the oldest held worktree. It reads the action log, the reports, `held.json` and `INDEX.csv` and changes nothing. Every `reclaim` report repeats the table under `## Metrics`, after the host sections.
- **Human actions (7d)** counts successful `approve PLAN ID`, `restore ID` and `find TERM` commands by the machine that ran them. Each command records its timestamp, host, command and item count in `storage-time.jsonl` under the report directory. A search with no matches still counts as one action. The column follows the time window selected by `--days`.
- Every `reclaim` run (dry run or apply) also rewrites `fleet/summary.md` in the report folder: per host, the after-run disk % from up to 30 retained `reclaim --apply` reports (sparkline, latest, min, max), bytes reclaimed in the displayed action window, worktrees held now by reason with the 5 largest, and the policy (`live`, idle days, `roots` and `archive` counts, archive entries with their own `days`). A separate managed-bytes table shows the latest apply observation, a 30-day trend when the retained observations support it, and counts of complete, partial, and unavailable reports in the last 30 days. This includes valid collected apply reports. Older reports without managed measurements contribute only to the unavailable count. If the logs cannot be read, the file says why; if it cannot be written, the run prints a warning and its exit code is unchanged.

`--to PATH` replaces the archived root, also with `--member`. For an archive rooted at `.scratch`, `--to /tmp/recovered --member .scratch/evidence.txt` writes `/tmp/recovered/evidence.txt`. `/tmp/recovered` must not already exist.

## Reports

Each run writes a timestamped Markdown report in the report folder. For each host it shows disk use before and after, and every proposed or applied action with its size. Skipped items are summed by reason, with counts and bytes, and the 20 largest are listed by path. Skipped paths are sized read-only in one batched check per tier, capped at 30 seconds; a note says when some sizes are lower bounds. Sizes are logical file sizes, and a skip does not count toward savings. A `reclaim` report also lists, per host, the 20 largest folders directly under home or a `roots` entry that no `archive` rule or worktree covers, with a hint such as "looks like scratch", "benchmark output" or "agent transcripts". That scan stops after 600 seconds per host or at the host's deadline, and coldcleaner never acts on what it lists. `reclaim --apply` keeps each folder's last size in `~/.cache/coldcleaner/unlisted.json` on that host; a folder not measured in time shows that size with its date, and a "Grew since the last scan" table lists folders that got bigger. Dry runs read the cache but never write it. In `--json`, each host carries them as `unlisted` with `unlisted_complete` and `grew`. A `reclaim` report opens with "Totals by category": items, reclaimable bytes (proposed plus done) and acted bytes for completed worktrees, scratch and temp, test and benchmark outputs, and archived agent artifacts. `--json` carries the same numbers as top-level `categories`, keyed `worktree`, `scratch`, `test-output` and `artifact`.

An optional top-level `attention_note` path names a Markdown file, such as a team notes channel. After each `reclaim --apply`, including a dry run started to obtain apply coverage, coldcleaner appends an `ATTENTION` line for hosts that remain unreachable over SSH after retry or have disk use at or above `alert_pct`. Apply also reports at least 1 GiB skipped due to the deletion limit and newly held worktrees. The line names the report. The held set is kept in `held.json` in the report folder; a host whose run had errors keeps its previous set, and a run that started before the last saved one leaves it unchanged. If the note cannot be written, the run exits 1. Without `attention_note`, nothing is written.

An optional top-level `manual_notes` array of one-line strings in the rules adds a final "Manual fixes, report only" section.

Dry runs still inspect the hosts over SSH. Long scans write progress to stderr every five seconds, with folder and file counts, bytes and elapsed time.

Worktree removal and preview rows also record `head`, `branch`, `remote`, `merged` (whether the head is an ancestor of the published `main`, or `master` when `main` is absent, proved by the probe or, when that commit is not fetched locally, by GitHub's compare API; false also covers unavailable proof), and `pull_requests` (PR URLs matching that exact head). To recreate a removed worktree, use a local checkout of the logged `remote` and run `git -C <repo> worktree add <path> <head>`. When the row has a branch that no longer exists locally, run `git -C <repo> worktree add -b <branch> <path> <head>` instead. If the branch was retained or is in use, restore the exact commit with `git -C <repo> worktree add --detach <path> <head>`.

Every reclaim row also names the policy it ran under: `rule` (`<host>.<key>:<value>`, the `roots` entry, or `archive` pattern that selected the path), `idle_days` (the idle window applied, or null when the row stopped before one was chosen or none applies), `rules_sha256` (SHA-256 of the rules file bytes) and `code` (the full Git commit of the controller checkout, or the installed package label).

`reclaim --apply` also appends one JSON line per action to `reclaim-actions.jsonl` in the report folder. When a new line would push that file past `actions_log_mb` (default 10), it is gzipped to `reclaim-actions-<UTC timestamp>.jsonl.gz`, read back and only then removed. Rotated files are kept; read them with `zcat`.

Each host acts on at most `max_items_per_run` items (default 200) and `max_gib_per_run` GiB (default 100) per `reclaim --apply`; a host table can override either. Once the next item would cross a limit, it and the rest on that host are skipped with `deletion limit reached`. If those skips total at least 1 GiB on a host, the run exits 3 with an `ATTENTION:` line unless it failed.

After reclaim writes a report, it keeps the newest 30 reports and newest 30 dry-run plans
in that report folder. It also keeps the newest plan for the current rules, the newest
complete dry-run report covering each host under those rules, and the plans paired with
those reports. Plans referenced by approvals, the fleet snapshot, or active or rotated
action logs stay available outside the 30-plan limit. Retention applies only to top-level
reclaim report and plan history. Recovery archives and action logs are kept.
Disk trends, disk space freed, and managed-artifact observations use retained reports.
Frequent scans can leave fewer days of disk history than the requested metrics window.

A host table can set `managed_bytes_target` to a positive integer in bytes. The fleet summary scores the latest apply observation against that target when coverage is complete. The 30-day trend requires retained complete observations with the same rules hash at least 30 days apart. Counts cover the last 30 days, and the comparison can use an older baseline.

### Approval mode

Every `reclaim` dry run writes `<report>.plan.json` next to its report, listing each candidate with a stable `id`, host, tier, path, bytes, rule and reason. The ID is a hash of the host, tier, path, Git head (worktrees) and every file's path, type, size, modification time and change time, so it stays the same while the item is unchanged. `coldcleaner approve PLAN ID...` records approvals in `approvals.json` in the report folder.

Items of a tier listed in the top-level `approval` array, or matched by an archive table entry with `approval = true`, are acted on by `reclaim --apply` only when their current ID is approved. Others are skipped with `APPROVAL NEEDED`; an approved item whose ID has changed since the plan is skipped with `APPROVAL STALE`. Each approved item still passes every fresh check before acting, and its ID is recomputed from the fresh check and again by the host right before removal, so a change after approval also skips it. An approval is used up once the item is acted on. On a native Windows controller, approve from the local plan using the same rules file and report folder as the nightly task. The ID uses NTFS change time and file identity. Filesystems where the probe cannot prove change time are held. Windows hosts reached over SSH still hold gated items with `APPROVAL UNAVAILABLE`. Tiers and entries without the flag act automatically, as before.

## Ranked disk usage

Run `coldcleaner top` to rank reclaimable worktrees and archive candidates from the latest recorded
reclaim snapshot. The default view omits WSL and hosts configured for report collection.
Run `coldcleaner reclaim --host HOST` first to get a fresh dry-run
snapshot. `top` reads that snapshot and prints the scan time. Use `--host HOST` to narrow the view.
For a local nightly with its own policy and report directory, use the same `--host HOST --local`
and, when applicable, the same `--report-dir` as the dry run. From source, use
`python3 -B -m coldcleaner top` to suppress Python's bytecode cache.

The ranking uses the byte estimates and safety decisions from the scan. Items deferred by the
deletion limit or waiting for approval also appear, with approval needs marked. A counted directory
includes its contents once, including any nested virtual environment or `node_modules`.
Standalone managed dependency directories get their own rows. Repo labels use recognizable
checkout names, with recorded GitHub origins as a fallback. Tool labels use directory names.
Unattributed labels read `unknown`.

`coldcleaner top --json` prints one object:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | `1` |
| `status` | string | `ok` or `incomplete` |
| `scanned` | object of strings | Host names mapped to scan timestamps in ISO 8601 |
| `missing_hosts` | array of strings | Selected hosts without a complete snapshot under the current rules |
| `items` | array of objects | Largest first. Each item has string `host`, `path`, `repo`, `tool`, and `category`, integer `bytes`, and boolean `approval` |
| `totals` | object | `repo`, `tool`, and `category` each map labels to integer byte totals |

A usable snapshot with no candidates gives an empty `items` array. Exit 0 means all selected
snapshots were usable. Exit 1 returns a versioned `refused` object with a `reason` string for invalid
options or rules. Exit 2 means at least one snapshot is missing or incomplete. Snapshots without
recorded coverage require a fresh scan. If the snapshot data cannot be read, the versioned
`incomplete` object contains a `reason` string.

## Calling it from another tool

`doctor --json` and `check-rules --json` each print one object with integer `schema_version` (currently 1) and string `status`.

- `doctor` returns `ok` on exit 0 or `attention` on exit 1. The `checks` array contains a string `name`, boolean `ok` and string `detail` for each check.
- `check-rules` returns `ok` on exit 0, with a `live` array of tier names and integer `alert_pct`.
- Both return `refused` on exit 1 for invalid rules and `incomplete` on exit 2 for usage or runtime errors. These objects contain a string `reason`.

`coldcleaner reclaim --rules /path/to/rules.toml --host local --json` is the stable entry point for other programs. With a pip install, or from the repository folder, `python3 -m coldcleaner reclaim --rules /path/to/rules.toml --host local --json` does the same. One JSON object goes to stdout and progress to stderr. Add `--apply` to act.

| JSON exit | `status` | Meaning |
| ---: | --- | --- |
| 0 | `ok` | The run completed without findings that need attention. |
| 1 | `attention` | At least one host completed and a host remained unreachable over SSH, or a host needs attention for disk pressure, deletion limits, or missing apply coverage. |
| 1 | `refused` | Reclaim refused to start because the rules are invalid or an apply prerequisite was unmet. |
| 2 | `incomplete` | Arguments were invalid, a file could not be read or written, a step failed, or no host completed after an SSH outage. |

Schema version 1 always includes integer `schema_version` and string `status`. A refusal, invalid arguments or a rules read error includes a string `reason`. Run summaries have these fields.

| Field | Type and meaning |
| --- | --- |
| `mode` | `dry-run` or `apply`. An apply request can produce a dry run if no host has current coverage. |
| `code` | String describing the running revision, or `null` if unavailable. |
| `report`, `plan` | Path strings, or `null` when the corresponding file was not written. Apply never writes a plan. |
| `errors` | Array of error strings that belong to no single host. |
| `categories` | Object keyed by `worktree`, `clone`, `scratch`, `test-output`, and `artifact`. Each entry has integer `items`, `reclaimable_bytes`, and `acted_bytes`. |
| `hosts` | Array of host objects. |
| `preview` | Present when apply also dry-runs uncovered hosts. This is a second run summary with the same schema version. The outer status and exit code cover both runs. |

Each host has string `name` and `attention` (empty when clear), boolean `unreachable`, and number-or-null `disk_before_percent` and `disk_after_percent`. Integers `would_free_bytes` and `acted_bytes` tally proposed and completed actions. The integer `skipped` counts skipped rows, whose reasons appear in the Markdown report. The `errors` and `notes` arrays contain strings. The `actions` array lists non-skip rows with string `tier`, `action`, `path` and `reason`, integer `bytes`, and tier-specific fields.

The report-only folder scan has a boolean `unlisted_complete`. Each `unlisted` row has strings `path` and `hint`, an integer `bytes`, a boolean `complete`, and a `measured` timestamp string when the size came from the cache. Each `grew` row has a string `path`, integer `bytes` and `before`, and the previous measurement's timestamp string `since`.

Each host's `managed_artifacts` object has integer-or-null `bytes` and a `coverage` of `complete`, `partial` or `unavailable`. The estimate includes observed worktrees, clones, and listed archive paths remaining after the scan. Unavailable measurements have null bytes. Overall disk percentages describe the whole filesystem. Nested build output in an independently eligible abandoned worktree is included in the worktree's measured bytes and follows the worktree's approval and verified archive.

## Limitations

- Projects with nested repositories need manual review.
- Tests use temporary folders, local Git remotes and fake hosts. They do not prove correctness on every remote system, so review every live configuration before use.

## Cleanup policy options

Set these in the existing rules file. The three switches accept `"on"` and `"off"`; omitted switches behave as `"on"`.

- `quarantine_days` is a positive integer, default **7**. A later archive-tier apply purges an expired local quarantine after checking the item and its protections again, including when NAS archiving has since been enabled. A change to the item or its host’s archive policy holds it for restore. Only a purge counts toward reclaimed bytes.
- `archive_before_delete = "off"` moves eligible non-Git items into a private sibling directory on the same filesystem. The action log and report include the quarantine path and the `coldcleaner restore quarantine:<host>:<id>` command. Restore returns the entire item to its original path, or to an unused path on the same filesystem with `--to`. The parent directory must exist. On a host that uses local reclaim, use `coldcleaner restore --local quarantine:<host>:<id>`. Standalone reclaim holds the restored item for a fresh recovery interval. A failed move holds the item. With archiving off, standalone rules may omit `nas_root`. Unpublished reflog history and Windows worktrees with ignored files remain held without a recovery archive. Archive-tier candidates containing Git repositories are held when copies are off; use the clone or worktree tier for Git retirement. Nested repositories, including bare repositories, hold candidates in every tier when copies are off.
- `backup_copy_check = "off"` skips archive read-back for fresh and reused copies. Source-change, archive-presence and drive-identity checks remain enforced.
- `notes_vault = "off"` skips artifact receipts quietly, even when the vault path or app is missing. With this setting absent or `"on"`, missing vaults and receipts still hold artifacts, exactly as before.
- `wait_period_days = 0` disables the wait. A nonnegative number overrides tier and entry windows, including the system-temp minimum. Omit it to retain existing windows.

Protected paths, active processes, Git publication proof, approvals and deletion limits remain enforced.

`fleet/summary.html` renders the same summary as a static page, with no server or JavaScript. Its waiting list shows all current holds, an unassigned owner when ownership is unavailable, and a shell-quoted approval command from the current host dry-run snapshot for approval holds. Safety holds show the action needed instead; approval cannot override them. The weekly storage line totals reclaim run minutes, including manual runs and dry runs and item approvals recorded in `storage-time.jsonl` since installation, not human time. Both summary files are replaced under the existing fleet lock.
The waiting list uses `fleet/waiting.json`, replaced per host from every current report action, including unsized skips; a newer host snapshot replaces previous approval previews. After an apply run, an approval hold asks for a fresh dry run.
