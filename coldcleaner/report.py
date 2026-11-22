import itertools
import json
import os
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import locking
from .disk import Usage
from .report_files import RECLAIM, action_line, cell, paths

SKIP_ROWS = 20
NOTE_PATHS = 5
PREVIEWED = 'Reclaim dry run complete for: '
MANAGED = 'Managed agent-artifact bytes: '
HELD = {
    'UNIQUE: unpushed commits or incomplete origin proof': 'push it, or point origin at the repo that has it',
    'IN USE: uncommitted work or stashes': 'commit or discard it',
    'IN USE: work is neither merged nor closed at this head': 'open, merge or close a PR',
    'IN USE: open pull request': 'merge or close the PR',
}


def size(value):
    return f'{value / 1024**3:.2f} GiB ({value} bytes)'


def usage(value):
    return 'unavailable' if value is None else f'{value.percent:.2f}% ({size(value.used)} of {size(value.total)})'


@dataclass
class HostReport:
    name: str
    before: Usage | None = None
    after: Usage | None = None
    actions: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    broad_references: list = field(default_factory=list)
    attention: str = ''
    unlisted: list = field(default_factory=list)
    unlisted_complete: bool = True
    grew: list = field(default_factory=list)
    unreachable: bool = False

    @property
    def would_free(self):
        return sum(row['bytes'] for row in self.actions if row['action'].startswith('would '))

    @property
    def acted_bytes(self):
        return sum(row['bytes'] for row in self.actions if acted(row))


CATEGORIES = {'worktree': 'Completed worktrees', 'clone': 'Redundant clones', 'scratch': 'Scratch and temp',
              'test-output': 'Test and benchmark outputs', 'artifact': 'Archived agent artifacts'}


def category(row):
    tier = row['tier']
    if tier in ('worktree', 'clone'):
        return tier
    if tier == 'archive':
        return row.get('category')


def categories(reports):
    totals = {key: dict(items=0, reclaimable_bytes=0, acted_bytes=0) for key in CATEGORIES}
    for row in (row for report in reports for row in report.actions):
        key = category(row)
        if key in totals and (row['action'].startswith('would ') or acted(row)):
            totals[key]['items'] += 1
            totals[key]['reclaimable_bytes'] += row['bytes']
            totals[key]['acted_bytes'] += row['bytes'] if acted(row) else 0
    return totals


def category_table(reports):
    lines = ['## Totals by category', '', '| Category | Items | Reclaimable bytes | Acted bytes |', '| --- | ---: | ---: | ---: |']
    for key, values in categories(reports).items():
        lines.append(f"| {CATEGORIES[key]} | {values['items']} | {values['reclaimable_bytes']} | {values['acted_bytes']} |")
    return lines + ['']


def acted(row):
    return not row['action'].startswith('would ') and row['action'] not in ('skip', 'error', 'report only', 'unreadable')


def action_table(lines, rows):
    lines.extend(['', '| Tier | Action | Path | Bytes | Reason |', '| --- | --- | --- | ---: | --- |'])
    lines.extend(map(action_line, rows))


def note_lines(notes):
    groups = {}
    for note in notes:
        kind = note.split(': ', 1)[0]
        groups.setdefault(kind if kind.endswith(', skipped') else note, []).append(note)
    for kind, group in groups.items():
        if len(group) == 1 or not kind.endswith(', skipped'):
            yield from (f'- Note: {cell(note)}' for note in group)
            continue
        paths = '; '.join(note.partition(': ')[2] for note in group[:NOTE_PATHS])
        first = f', first {NOTE_PATHS}' if len(group) > NOTE_PATHS else ''
        yield f'- Note: {cell(kind)}: {len(group)} paths{first}: {cell(paths)}'


def held(row):
    if row['tier'] == 'worktree' and row['action'] == 'skip':
        return next((reason for reason in HELD if row['reason'].startswith(reason)), None)


def needs_person(reports):
    rows = [(report.name, row, reason) for report in reports for row in report.actions if (reason := held(row))]
    full = [f'- {report.name}: {cell(report.attention)}' for report in reports if report.attention]
    if not rows and not full:
        return []
    lines = ['## Needs a person', '', *full]
    if rows:
        lines.extend(['', '| Held because | Worktrees | GiB | To release |', '| --- | ---: | ---: | --- |'])
        for reason, todo in HELD.items():
            matched = [row for _, row, found in rows if found == reason]
            if matched:
                lines.append(f"| {reason} | {len(matched)} | {sum(row['bytes'] for row in matched) / 1024**3:.2f} | {todo} |")
        lines.extend(['', f'Largest {SKIP_ROWS} held:', '', '| Host | Path | GiB | Reason |', '| --- | --- | ---: | --- |'])
        for name, row, _ in sorted(rows, key=lambda item: item[1]['bytes'], reverse=True)[:SKIP_ROWS]:
            lines.append(f"| {cell(name)} | {cell(row['path'])} | {row['bytes'] / 1024**3:.2f} | {cell(row['reason'])} |")
    return lines + ['']


def inside(path, parent):
    parent = parent.rstrip('/\\')
    return path == parent or path.startswith((parent + '/', parent + '\\'))


def outermost(rows, removed=()):
    covered = {row['path'].rstrip('/\\') for _, row in removed}
    for index, row in sorted(rows, key=lambda item: (len(item[1]['path']), -item[0])):
        path = row['path']
        if path in covered or any(path[:separator.start()] in covered for separator in re.finditer(r'[/\\]', path)):
            continue
        covered.add(path.rstrip('/\\'))
        yield index, row


def remaining(rows, removed):
    for index, row in outermost(rows, removed):
        freed = sum(gone['bytes'] for later, gone in removed if later > index and inside(gone['path'], row['path']))
        yield row, max(0, row['bytes'] - freed)


def managed_partial(entry):
    return incomplete(entry) or any('skip sizes' in note or note.startswith('Unreadable, skipped') for note in entry.notes)


def managed(report):
    rows = [(index, row) for index, row in enumerate(report.actions)
            if row['tier'] in ('worktree', 'clone', 'archive') and row['reason'] != 'package caches are excluded']
    if not rows and (incomplete(report) or report.after is None or any(row['tier'] == 'execution' for row in report.actions)):
        return dict(bytes=None, coverage='unavailable')
    removed = [(index, row) for index, row in rows if acted(row)]
    pending = ((index, row) for index, row in rows if not acted(row))
    managed = sum(size for _, size in remaining(pending, removed))
    return dict(bytes=managed, coverage='partial' if managed_partial(report) else 'complete')


def scope(report):
    if report.after is None or 'alert_pct' not in report.attention:
        return []
    sample = managed(report)
    if sample['bytes'] is None:
        return []
    partial = sample['coverage'] == 'partial'
    tail = 'Sizing was incomplete, so part of the rest may also be in scope.' if partial else "The rest is outside Coldcleaner's scope."
    return [f"- Used {report.after.used / 1024**3:.2f} GiB; {'at least ' if partial else ''}{sample['bytes'] / 1024**3:.2f} GiB of it "
            f"is in Coldcleaner's managed scope (listed archive paths, worktrees and clones). {tail}"]


def unlisted(report):
    if not report.unlisted and report.unlisted_complete:
        return []
    lines = ['', '### Large unlisted folders, report only', '',
             'Folders under home or the configured roots that no rule covers. coldcleaner never acts on them; '
             'archive targets and worktrees inside them are left out of these sizes and follow their own rules.']
    if not report.unlisted_complete:
        lines.append('The scan was incomplete (time cap, unreadable folders or a failed probe), so folders may be missing and some sizes are lower bounds.')
    lines.extend(['', '| Path | GiB | Hint |', '| --- | ---: | --- |'])
    for row in report.unlisted:
        gib = f"{'' if row['complete'] else 'at least '}{row['bytes'] / 1024**3:.2f}"
        if row.get('measured'):
            gib += f" (as of {row['measured'][:10]})"
        lines.append(f"| {cell(row['path'])} | {gib} | {cell(row['hint'])} |")
    if report.grew:
        lines.extend(['', '### Grew since the last scan, report only', '',
                      '| Path | Grew GiB | Now GiB | Last measured |', '| --- | ---: | ---: | --- |'])
        for row in report.grew:
            lines.append(f"| {cell(row['path'])} | {(row['bytes'] - row['before']) / 1024**3:.2f} | "
                         f"{row['bytes'] / 1024**3:.2f} | {row['since']} |")
    return lines


def held_state(path):
    state = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(state, dict):
        raise ValueError(f'{path} is malformed')
    result = {}
    for name, value in state.items():
        if not (isinstance(value, dict) and isinstance(value.get('started'), str) and isinstance(value.get('paths'), list)
                and all(isinstance(item, str) for item in value['paths'])):
            raise ValueError(f'{path} is malformed')
        started = datetime.fromisoformat(value['started'])
        if started.tzinfo is None:
            raise ValueError(f'{path} is malformed')
        result[name] = started, set(value['paths'])
    return result


def incomplete(entry):
    return bool(entry.errors) or any(row['action'] == 'error' for row in entry.actions)


def append_attention(note, report_path, parts):
    now = datetime.now(timezone.utc)
    Path(note).parent.mkdir(parents=True, exist_ok=True)
    with Path(note).open('a', encoding='utf-8') as stream:
        stream.write(f"\n### {now:%Y-%m-%d} · coldcleaner\nATTENTION coldcleaner at {now:%Y-%m-%dT%H:%MZ}: "
                     f"{'; '.join(parts)}. Report: {report_path}\n")


def announce(reports, directory, note, report_path, started, *, preview=False):
    directory = Path(directory)
    parts = [f'{entry.name}: {entry.attention}' for entry in reports if entry.attention]
    if preview and not parts:
        return
    with (directory / 'reclaim-actions.lock').open('a') as lock:
        locking.lock(lock)
        if preview:
            append_attention(note, report_path, parts)
            return
        current = {entry.name: {row['path'] for row in entry.actions if held(row)} for entry in reports}
        state = directory / 'held.json'
        previous = held_state(state)
        fresh = [entry for entry in reports if entry.name not in previous or previous[entry.name][0] <= started]
        new = sum(len(current[entry.name] - previous.get(entry.name, (started, set()))[1]) for entry in fresh)
        if new:
            parts.append(f'{new} new held worktrees ({sum(map(len, current.values()))} held)')
        if parts:
            append_attention(note, report_path, parts)
        for entry in fresh:
            kept = previous.get(entry.name, (started, set()))[1] if incomplete(entry) else set()
            previous[entry.name] = started, current[entry.name] | kept
        temporary = state.with_suffix(f'.{os.getpid()}.tmp')
        temporary.write_text(json.dumps({name: dict(started=at.isoformat(), paths=sorted(paths))
                                         for name, (at, paths) in previous.items()}), encoding='utf-8')
        temporary.replace(state)


def render(reports, apply=False, code=None, manual_notes=(), rules_sha256=None, reclaim=False, footer=()):
    now = datetime.now(timezone.utc)
    lines = [f'# coldcleaner {now:%Y-%m-%d %H:%M:%S} UTC', '',
             f'Mode: {"apply, limited to live tiers" if apply else "dry run"}. Byte estimates are logical file sizes, not guaranteed free space.', '']
    previewed = [entry.name for entry in reports if not incomplete(entry)]
    if reclaim and not apply and previewed:
        lines[2:2] = [f"{PREVIEWED}{', '.join(previewed)}", '']
    if reclaim:
        lines[2:2] = [RECLAIM, '']
    if rules_sha256:
        lines[2:2] = [f'Rules: sha256 {rules_sha256}', '']
    if code:
        lines[2:2] = [f'Code: {code}', '']
    if reclaim:
        lines.extend(category_table(reports))
    lines.extend(needs_person(reports))
    for report in reports:
        lines.extend([f'## {report.name}', '', f'Before: {usage(report.before)}', '',
                      f'After: {usage(report.after)}', '', f'Would free: {size(report.would_free)}', ''])
        if apply:
            lines.extend([f'Acted on: {size(report.acted_bytes)}', ''])
        if report.attention:
            lines.append(f'- ATTENTION: {cell(report.attention)}')
        if reclaim:
            sample = managed(report)
            observed = 'unavailable' if sample['bytes'] is None else f"{size(sample['bytes'])}; coverage {sample['coverage']}"
            lines.extend([MANAGED + observed, ''])
        else:
            lines.extend(scope(report))
        lines.extend(f'- {cell(error)}' for error in report.errors)
        lines.extend(note_lines(report.notes))
        if report.broad_references:
            lines.extend(['', 'Broad scheduler references, equality only: '
                          + ', '.join(map(cell, report.broad_references)), ''])
        skips = [row for row in report.actions if row['action'] == 'skip']
        action_table(lines, [row for row in report.actions if row['action'] != 'skip'])
        lines.extend(['', f'### Skipped: {len(skips)}', '', '| Reason | Count | Bytes |', '| --- | ---: | ---: |'])
        reasons = Counter(row['reason'] for row in skips)
        for reason, count in reasons.most_common():
            lines.append(f"| {cell(reason)} | {count} | {sum(row['bytes'] for row in skips if row['reason'] == reason)} |")
        lines.extend(['', f'Largest {SKIP_ROWS} skipped:'])
        action_table(lines, sorted(skips, key=lambda row: row['bytes'], reverse=True)[:SKIP_ROWS])
        lines.extend(unlisted(report))
        lines.append('')
    lines.extend(footer)
    if manual_notes:
        lines.extend(['## Manual fixes, report only', '', *(f'- {note}' for note in manual_notes), ''])
    return '\n'.join(lines)


def write(reports, directory, apply=False, code=None, manual_notes=(), rules_sha256=None, reclaim=False, footer=()):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f'{datetime.now(timezone.utc):%Y-%m-%d-%H%M%S-%f}-{uuid.uuid4().hex}.md'
    temporary = path.with_suffix(f'.{os.getpid()}.tmp')
    try:
        temporary.write_text(render(reports, apply, code, manual_notes, rules_sha256, reclaim, footer), encoding='utf-8', errors='backslashreplace')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def dry_run_hosts(path, rules_sha256=None):
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return set()
    lines = list(itertools.takewhile(lambda line: not line.startswith('## '), text.split('\n')))
    if not any(line.startswith('Mode: dry run.') for line in lines):
        return set()
    if rules_sha256 is not None and f'Rules: sha256 {rules_sha256}' not in lines:
        return set()
    return {name for line in lines if line.startswith(PREVIEWED) for name in line.removeprefix(PREVIEWED).split(', ')}


def total(lines, label):
    found = [int(match.group(1)) for line in lines if (match := re.fullmatch(rf'{label}: .*\((\d+) bytes\)', line))]
    return size(sum(found)) if found else None


def summarize(path):
    try:
        lines = Path(path).read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return ['  Could not read this report.']
    written = re.fullmatch(r'# coldcleaner (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC)', lines[0]) if lines else None
    mode = next((m.group(1) for line in lines if (m := re.match(r'Mode: (apply|dry run)\b', line))), None)
    parts = [('Written', written and written.group(1)), ('Mode', mode),
             ('Would free', total(lines, 'Would free')), ('Acted on', total(lines, 'Acted on'))]
    return [f'  {label}: {value}' for label, value in parts if value]
