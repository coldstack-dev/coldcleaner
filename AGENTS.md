# AGENTS.md

Agent guide for installing and running Coldcleaner. Dry-run is the default: nothing is deleted or moved unless `--apply` is passed **and** the tier is listed in `live` in `rules.toml`.

## Setup and safe commands

- **Install (Python 3.14+):** `uv tool install git+https://github.com/coldstack-dev/coldcleaner@v0.3.3` (or `uv tool install .` from a clone).
- **Check prerequisites:** `coldcleaner doctor --json` and `coldcleaner check-rules --json`
- **Inspect disk & last report:** `coldcleaner status --host local`
- **Preview cleanup (dry run):** `coldcleaner reclaim --host local --json` (add `--no-gh` to skip GitHub PR queries)
- **Preview CoW worktree dedupe (dry run):** `coldcleaner reflink --json /path/to/roots` (Linux Btrfs/XFS apply; APFS dry-run only)

## Exit codes

| Mode | `0` | `1` | `2` | `3` |
| --- | --- | --- | --- | --- |
| Text (`reclaim`) | Completed | Failed / no host completed | Refused / invalid args or rules | Attention (disk `>= alert_pct`, isolated outage, limit, or uncovered apply) |
| `--json` (`reclaim`, `doctor`, `check-rules`) | `ok` | `attention` or `refused` | `incomplete` (invalid args or runtime error) | — |

## Approval rules

- **Never run mutating commands without explicit user approval:** `--apply` (`reclaim`, `reflink`, `triage`), `init` (with or without `--yes`), `restore`, and `approve`.
- Never run `coldcleaner approve` to authorize plan items without the user explicitly approving the IDs.
- Always run a dry run first, read the report/JSON summary, and show proposed paths and bytes before asking to apply. See [README.md](README.md) and [docs/reference.md](docs/reference.md).
