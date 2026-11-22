import argparse
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import collect, disk, doctor, fleet, hosts, metrics, protect, reclaim, report, store, rules, version

RETRY_SECONDS = 30
JSON_SCHEMA_VERSION = 1
STANDARD_JSON_COMMANDS = ('reclaim', 'doctor', 'check-rules')
JSON_RUN_EXIT = {0: 0, 1: 2, 3: 1}
APPLY_SKIPPED = 'apply skipped: no complete reclaim dry-run report with the current rules; a dry run follows so it can apply next run'


def measure(host, progress):
    try:
        return disk.measure(host)
    except Exception as exc:
        print(f'{host.name}: unreachable ({exc}); retrying in {RETRY_SECONDS}s', **progress)
        time.sleep(RETRY_SECONDS)
        return disk.measure(host)


def summary(reports, apply, path, code, status, errors, plan=None):
    def percent(usage):
        return None if usage is None else round(usage.percent, 2)
    return dict(schema_version=JSON_SCHEMA_VERSION, status=status, mode='apply' if apply else 'dry-run',
                code=code, report=path and str(path),
                plan=plan and str(plan), errors=list(errors),
                categories=report.categories(reports),
                hosts=[dict(name=entry.name, disk_before_percent=percent(entry.before), disk_after_percent=percent(entry.after),
                            unreachable=entry.unreachable, attention=entry.attention, managed_artifacts=report.managed(entry),
                            would_free_bytes=entry.would_free, acted_bytes=entry.acted_bytes, errors=entry.errors, notes=entry.notes,
                            skipped=sum(row['action'] == 'skip' for row in entry.actions),
                            actions=[row for row in entry.actions if row['action'] != 'skip'],
                            unlisted=entry.unlisted, unlisted_complete=entry.unlisted_complete, grew=entry.grew)
                       for entry in reports])


def failure_reasons(reports, errors):
    reasons = list(errors)
    for entry in reports:
        reasons += [f'{entry.name}: {problem}' for problem in entry.errors]
        failed_rows = [row for row in entry.actions if row['action'] == 'error']
        if failed_rows:
            first = failed_rows[0]
            reasons.append(f"{entry.name}: {len(failed_rows)} error action(s), first {first['path']}: {first['reason']}")
    return reasons


def outage_without_completion(reports):
    return any(entry.unreachable for entry in reports) and not any(
        entry.after is not None and not report.incomplete(entry) for entry in reports)


def run(config, chosen_hosts, apply=False, *, as_json=False, deadline=None, skipped=(), automatic_preview=False,
        collect_reports=False, fleet_reports=None):
    run_started = datetime.now(timezone.utc)
    code = version.describe()
    progress = dict(file=sys.stderr if as_json else sys.stdout, flush=True)
    reports = []
    scanned = {}
    errors = []
    failed = False
    deadline = deadline or time.monotonic() + reclaim.RUN_SECONDS
    for index, host in enumerate(chosen_hosts):
        scanned[host.name] = datetime.now(timezone.utc).isoformat()
        entry = report.HostReport(host.name)
        reports.append(entry)
        if time.monotonic() >= deadline:
            entry.errors.append('not started: ' + reclaim.DEADLINE)
            failed = True
            continue
        print(f'{host.name}: inspect', **progress)
        try:
            entry.before = measure(host, progress)
        except Exception as exc:
            entry.errors.append('Host unreachable or disk measurement unavailable: ' + str(exc))
            entry.unreachable = bool(host.ssh and isinstance(exc, subprocess.CalledProcessError) and exc.returncode == 255)
            if entry.unreachable:
                entry.attention = 'host unreachable after retry; scan skipped'
            else:
                failed = True
            continue
        try:
            if host.kind == 'wsl':
                entry.notes.append('Disk gating uses the Windows bridge C:, which contains the WSL virtual disk.')
                reclaim.Reclaimer(host, config, apply, None, entry).log('execution', '', 'skip', 0,
                    'Windows WSL execution is retired', rule=f'{host.name}.kind:wsl', idle_days=None)
            else:
                protection = protect.collect(host)
                entry.broad_references = sorted(path for path in protection.paths
                    if protect.broad_reference(path, protection.home, host.kind == 'powershell'))
                cleaner = reclaim.Reclaimer(host, config, apply, protection, entry)
                later = len(chosen_hosts) - index - 1 + len(skipped)
                now = time.monotonic()
                cleaner.deadline = max(deadline - reclaim.HOST_RESERVE_SECONDS * later, now + (deadline - now) / (later + 1))
                for tier in ('worktrees', 'clones', 'archives', 'unlisted'):
                    if time.monotonic() >= cleaner.deadline:
                        entry.errors.append(f'{tier} not started: {reclaim.DEADLINE}')
                        failed = True
                        continue
                    started = time.monotonic()
                    print(f'{host.name}: {tier} start', **progress)
                    try:
                        getattr(cleaner, tier)()
                    except Exception as exc:
                        entry.errors.append(f'{tier} incomplete: {reclaim.describe(exc)}')
                        failed = True
                    items = sum(action['tier'] == tier.removesuffix('s') for action in entry.actions)
                    print(f'{host.name}: {tier} done, {items} items, {time.monotonic() - started:.0f}s', **progress)
        except Exception as exc:
            entry.errors.append('Protection inventory unavailable; cleanup skipped: ' + str(exc))
            failed = True
        finally:
            try:
                entry.after = disk.measure(host)
            except Exception as exc:
                entry.errors.append('Final disk measurement unavailable: ' + str(exc))
                failed = True
        if entry.errors or any(action['action'] == 'error' for action in entry.actions):
            failed = True
        alerts = []
        if entry.after and entry.after.percent >= config['alert_pct']:
            alerts.append(f"disk {entry.after.percent:.2f}% is at or above alert_pct {config['alert_pct']}%")
        waiting_bytes = sum(row['bytes'] for row in entry.actions
                            if row['action'] == 'skip' and row['reason'] == reclaim.LIMIT_REACHED)
        if waiting_bytes >= 1024**3:
            alerts.append('deletion limit reached (max_items_per_run or max_gib_per_run); the rest waits for the next run')
        entry.attention = '; '.join(alerts)
    scanned_reports = list(reports)
    if fleet_reports is None:
        failed |= outage_without_completion(scanned_reports)
    else:
        fleet_reports.extend(scanned_reports)
    reports += [report.HostReport(name, attention=APPLY_SKIPPED) for name in skipped]
    if collect_reports:
        errors.extend(collect.run(config))
        failed |= bool(errors)
    footer = metrics_footer(config, scanned_reports if apply else ())
    if errors:
        footer.extend(['## Collection failures', '', *(f'- {report.cell(error)}' for error in errors), ''])
    try:
        path = report.write(reports, config['report_dir'], apply, code, config.get('manual_notes', ()),
                            config.get('rules_sha256'), True, footer)
    except OSError as exc:
        path, failed = None, True
        problem = 'Report not written: ' + str(exc)
        (reports[0].errors if reports else errors).append(problem)
    plan = None
    if path and not apply:
        try:
            plan = reclaim.write_plan(path.with_suffix('.plan.json'), reports, config.get('rules_sha256'))
        except OSError as exc:
            failed = True
            (reports[0].errors if reports else errors).append('Plan not written: ' + str(exc))
    if path and (apply or automatic_preview) and config.get('attention_note'):
        try:
            report.announce(scanned_reports, config['report_dir'], config['attention_note'], path, run_started,
                            preview=automatic_preview)
        except (OSError, ValueError) as exc:
            failed = True
            (reports[0].errors if reports else errors).append('Attention note not written: ' + str(exc))
    if path:
        try:
            fleet.write(config, seconds=(datetime.now(timezone.utc) - run_started).total_seconds(),
                        reports=scanned_reports, plan=plan, scanned=scanned, run_report=path)
        except OSError as exc:
            print(f'coldcleaner: fleet summary not written: {exc}', file=sys.stderr, flush=True)
    if failed:
        for reason in failure_reasons(reports, errors):
            print('coldcleaner: FAILED: ' + reason, file=sys.stderr, flush=True)
    for entry in reports:
        if entry.attention:
            print(f'coldcleaner: ATTENTION: {entry.name}: {entry.attention}', file=sys.stderr, flush=True)
    if as_json:
        result = exit_code(failed, reports)
        status = {0: 'ok', 1: 'incomplete', 3: 'attention'}[result]
        print(json.dumps(summary(reports, apply, path, code, status, errors, plan), default=str))
        return result
    print(path or problem)
    if plan:
        print(f'Plan: {plan}')
    for entry in reports:
        acted = f'; acted on {report.size(entry.acted_bytes)}' if apply else ''
        print(f'{entry.name}: {report.usage(entry.before)} -> {report.usage(entry.after)}; would free {report.size(entry.would_free)}{acted}')
    return exit_code(failed, reports)


def metrics_footer(config, current):
    try:
        rows = metrics.render(metrics.compute(config['report_dir'], config.get('nas_root'), current=current))
    except Exception as exc:
        rows = ['Metrics unavailable: ' + report.cell(exc)]
    return ['## Metrics', '', *rows, '']


def record_human_action(config, command, items):
    directory = Path(config['report_dir'])
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fleet.event(directory, host=socket.gethostname(), command=command, items=items)
    except OSError as exc:
        print(f'coldcleaner: {command} completed; storage time not recorded: {exc}', file=sys.stderr)


def exit_code(failed, reports):
    return 1 if failed else 3 if any(entry.attention for entry in reports) else 0


class PrintVersion(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, default=argparse.SUPPRESS, help='Print the coldcleaner version and exit.')

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            number = version.number()
        except (OSError, ValueError, KeyError, ImportError) as exc:
            parser.exit(1, f'coldcleaner: version unknown: {exc}\n')
        print(f'coldcleaner {number}')
        parser.exit()


def positive(text):
    if not text.isdigit() or int(text) < 1:
        raise argparse.ArgumentTypeError(f'must be a positive whole number of days, got {text!r}')
    return int(text)


def parser():
    result = argparse.ArgumentParser(prog='coldcleaner', description='Free disk space from finished Git worktrees and idle listed folders. '
                                     'Cleanup is a dry run unless you pass --apply.')
    result.add_argument('--version', action=PrintVersion)
    commands = result.add_subparsers(dest='command', required=True)
    descriptions = {
        'init': 'Configure cleanup policy in the existing rules file with six questions.',
        'reclaim': 'Remove finished Git worktrees and idle listed folders, after checking GitHub, running programs and coding agents and verifying an archive copy.',
        'status': 'Show disk usage per host and the last report.',
        'find': 'Search archives and their file lists.',
        'restore': 'Restore an archive to its original host or recover a legacy archive on a POSIX host.',
        'check-rules': 'Validate a rules file offline.',
        'doctor': 'Check prerequisites read-only and print PASS or FAIL for each.',
        'top': 'Rank reclaimable clutter from recent reclaim scans without changing files.',
        'metrics': 'Print per-host cleanup metrics from the action log, reports and archive index.',
        'restore-drill': 'Restore one random archive into a scratch folder on this machine, check it against its file list and SHA-256s, '
                         'delete the copy and log pass or fail. Exit 1 on fail.',
        'approve': 'Approve items from a reclaim dry-run plan so reclaim --apply may act on them.',
    }
    for name, description in descriptions.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument('--rules', type=Path, default=rules.DEFAULT_PATH, help='Read configuration from this rules file.')
        if name in ('reclaim', 'status', 'doctor', 'top'):
            command.add_argument('--host', help='Select one host instead of all hosts.')
        if name in ('reclaim', 'doctor', 'top'):
            command.add_argument('--local', action='store_true', help='Run --host on this machine without ssh (its own nightly).')
        if name == 'init':
            command.add_argument('--yes', action='store_true', help='Retain current settings without prompting.')
        if name in STANDARD_JSON_COMMANDS:
            command.add_argument('--json', action='store_true', help='Print one versioned JSON result. '
                                 'Exit 0 on success, 1 for findings or refusal, or 2 for usage or runtime errors.')
        if name == 'reclaim':
            command.add_argument('--apply', action='store_true', help='Perform actions enabled by the rules instead of a dry run.')
            command.add_argument('--i-reviewed', type=Path, metavar='REPORT',
                                 help='Require this complete dry-run report to cover the selected hosts and current rules.')
        if name == 'top':
            command.add_argument('--json', action='store_true', help='Print one JSON breakdown.')
        if name == 'metrics':
            command.add_argument('--days', type=positive, default=metrics.DAYS, help=f'Count the last N days (default {metrics.DAYS}).')
        if name == 'approve':
            command.add_argument('plan', type=Path, help='The .plan.json file written next to a reclaim dry-run report.')
            command.add_argument('ids', nargs='+', metavar='ID', help='Item IDs from the plan, or all.')
        if name in ('reclaim', 'status', 'doctor', 'metrics', 'restore-drill', 'approve', 'top'):
            command.add_argument('--report-dir', type=Path, help='Use this directory for cleanup reports.')
        if name == 'find':
            command.add_argument('term', help='Search archive records and file paths for this text.')
        if name == 'restore':
            command.add_argument('id', help='Restore the archive or local quarantine entry with this ID.')
            command.add_argument('--local', action='store_true', help='Restore a quarantine entry on this machine.')
            command.add_argument('--to', help='Replace the archived root with this path, including with --member.')
            command.add_argument('--member', help='Restore only this path within the archive.')
            command.add_argument('--to-host', help='Recover a legacy archive on this POSIX host. Requires --to.')
    return result


def rules_problem(path, exc):
    return f'coldcleaner: {path}: ' + ' '.join(str(exc).splitlines())


def pressure_note(usage, config):
    if usage.percent >= config['alert_pct']:
        return f"  (at or above alert level {config['alert_pct']}%)"
    return ''


def print_archive(record):
    print(f'{record.id}  {record.host}:{record.source_path}  '
          f'archived {record.archived_at}  {record.status}  '
          f'{record.file_count} files, {report.size(record.original_bytes)} '
          f'({report.size(record.archive_bytes)} stored)')
    for member in record.matches:
        print(f'  member {member}')


def restore_drill(config, scratch):
    try:
        row = reclaim.drill(config['nas_root'], config['report_dir'], scratch)
    except Exception as exc:
        print(f'restore drill fail: {exc}')
        return 1
    reason = f" ({row['reason']})" if row['reason'] else ''
    print(f"restore drill {row['result']}: {row['host']} {row['id']} {row['archive']}{reason}")
    return 0 if row['result'] == 'pass' else 1


def json_failure(message, code):
    print(json.dumps(dict(schema_version=JSON_SCHEMA_VERSION,
                          status='refused' if code == 1 else 'incomplete', reason=message)))
    return code


def refuse(args, message, *, code=1):
    if getattr(args, 'json', False):
        return json_failure(message, code)
    print(message)
    return 2


def apply_and_preview(config, ready, missing, as_json, **run_options):
    deadline = time.monotonic() + reclaim.RUN_SECONDS
    outputs = [io.StringIO(), io.StringIO()]
    fleet_reports = []
    with contextlib.redirect_stdout(outputs[0] if as_json else sys.stdout):
        applied = run(config, ready, True, as_json=as_json, deadline=deadline, fleet_reports=fleet_reports,
                      skipped=[host.name for host in missing])
    with contextlib.redirect_stdout(outputs[1] if as_json else sys.stdout):
        previewed_code = run(config, missing, False, as_json=as_json, deadline=deadline,
                             automatic_preview=True, fleet_reports=fleet_reports, **run_options)
    result = 1 if 1 in (applied, previewed_code) or outage_without_completion(fleet_reports) else max(applied, previewed_code)
    if as_json:
        combined, preview = (json.loads(output.getvalue()) for output in outputs)
        print(json.dumps(dict(combined, status={0: 'ok', 1: 'incomplete', 3: 'attention'}[result], preview=preview)))
    return result


def previewed(config, selected):
    sha = config.get('rules_sha256')
    covered = set().union(*(report.dry_run_hosts(path, sha) for path in report.paths(config['report_dir'])))
    return [host for host in selected if host.name in covered]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = parser().parse_args(argv)
    except SystemExit as exc:
        if exc.code == 2 and argv and '--json' in argv:
            if argv[0] in STANDARD_JSON_COMMANDS:
                return json_failure('invalid arguments; see stderr', 2)
            if argv[0] == 'top':
                return json_failure('invalid arguments; see stderr', 1)
        raise
    if args.command == 'init':
        from . import setup
        try:
            setup.configure(args.rules, args.yes)
        except (OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
            return refuse(args, rules_problem(args.rules, str(exc) or 'input ended; settings unchanged'))
        return 0
    local = getattr(args, 'local', False)
    if local and args.command == 'restore':
        parts = args.id.split(':')
        if len(parts) != 3 or parts[0] != 'quarantine':
            return refuse(args, '--local requires a quarantine ID')
        args.host = parts[1]
    if local and not args.host:
        return refuse(args, 'coldcleaner: --local needs --host naming this machine',
                      code=2 if args.command in STANDARD_JSON_COMMANDS else 1)
    try:
        overrides = {'local': args.host} if local else {}
        report_dir = getattr(args, 'report_dir', None)
        if os.name == 'nt' and report_dir is not None:
            overrides['report_dir'] = report_dir.absolute()
        config = rules.load(args.rules, **overrides)
    except (OSError, ValueError) as exc:
        message = rules_problem(args.rules, exc)
        code = 2 if isinstance(exc, (OSError, UnicodeDecodeError, rules.LocalHostError)) else 1
        if args.command == 'check-rules' and not args.json:
            print(message)
            return code
        return refuse(args, message, code=code if args.command in STANDARD_JSON_COMMANDS else 1)
    for option in ('host', 'to_host'):
        name = getattr(args, option, None)
        if name is not None and name not in hosts.HOSTS:
            return refuse(args, f'coldcleaner: unknown --{option.replace("_", "-")} host: {name}; known hosts: {", ".join(sorted(hosts.HOSTS))}',
                          code=2 if args.command in STANDARD_JSON_COMMANDS else 1)
    if getattr(args, 'to_host', None) and hosts.HOSTS[args.to_host].kind != 'posix':
        return refuse(args, 'coldcleaner: --to-host requires a POSIX host')
    if args.command == 'reclaim' and args.apply and not {'worktree', 'clone', 'archive'} & set(config['live']):
        return refuse(args, 'coldcleaner: reclaim --apply refused: none of worktree, clone or archive is listed in live')
    if args.command == 'reclaim' and args.apply and config.get('archive_before_delete', 'on') != 'off':
        if os.name == 'nt':
            try:
                reclaim.check_nas(config['nas_root'])
            except (OSError, RuntimeError) as exc:
                return refuse(args, f'coldcleaner: reclaim --apply refused: {exc}')
        elif not Path(config['nas_root']).is_dir():
            return refuse(args, f"coldcleaner: reclaim --apply refused: nas_root {config['nas_root']} does not exist; "
                                'create it on a network share (NFS or SMB) or under local_archive_mount (see docs/reference.md#archive-storage)')
    if 'nas_root' not in config and (args.command in ('find', 'restore-drill')
                                     or args.command == 'restore' and not args.id.startswith('quarantine:')):
        return refuse(args, 'this archive command requires nas_root')
    if args.command == 'check-rules':
        if args.json:
            print(json.dumps(dict(schema_version=JSON_SCHEMA_VERSION, status='ok', live=config['live'],
                                  alert_pct=config['alert_pct'])))
        else:
            live = ', '.join(config['live']) or 'none'
            print(f"OK: {args.rules} (live: {live}; alert {config['alert_pct']}%)")
        return 0
    try:
        if report_dir is not None and os.name != 'nt':
            config['report_dir'] = str(args.report_dir.resolve())
        selected = [hosts.HOSTS[args.host]] if getattr(args, 'host', None) else list(hosts.HOSTS.values())
        if args.command in ('reclaim', 'doctor') and not args.host:
            selected = [hosts.HOSTS[name] for name in config['reclaim_hosts']]
        if args.command == 'doctor':
            if not args.json:
                return doctor.main(config, selected)
            checks = [dict(name=name, ok=ok, detail=detail) for name, (ok, detail) in doctor.checks(config, selected)]
            failed = any(not check['ok'] for check in checks)
            print(json.dumps(dict(schema_version=JSON_SCHEMA_VERSION,
                                  status='attention' if failed else 'ok', checks=checks)))
            return int(failed)
        if args.command == 'restore-drill':
            return restore_drill(config, Path.home() / '.cache' / 'coldcleaner' / 'restore-drill')
        if args.command == 'approve':
            chosen = reclaim.approve(config['report_dir'], args.plan, args.ids)
            record_human_action(config, args.command, len(chosen))
            print(f"approved {len(chosen)} items in {Path(config['report_dir']) / reclaim.APPROVALS}: {', '.join(chosen) or 'none'}")
            return 0
        if args.command == 'top':
            from . import top
            if not args.host:
                selected = [host for host in selected if host.kind != 'wsl' and host.name not in config['collect_hosts']]
            result = top.breakdown(config, selected)
            if args.json:
                print(json.dumps(dict(schema_version=JSON_SCHEMA_VERSION, **result)))
            else:
                top.print_breakdown(result)
            return 2 if result['missing_hosts'] else 0
        if args.command == 'metrics':
            print('\n'.join(metrics.render(metrics.compute(config['report_dir'], config.get('nas_root'), args.days), args.days)))
            return 0
        if args.command == 'reclaim':
            collection = {'collect_reports': True} if args.apply and not args.host and config.get('collect_hosts') else {}
            if args.apply and args.i_reviewed is not None:
                covered = report.dry_run_hosts(args.i_reviewed, config.get('rules_sha256'), strict=True)
                missing = [host.name for host in selected if host.name not in covered]
                if missing:
                    return refuse(args, f"coldcleaner: reclaim --apply refused: {args.i_reviewed} is not a complete "
                                  f"reclaim dry-run report with the current rules for {', '.join(missing)}")
            automatic_preview = args.apply and args.i_reviewed is None
            ready = previewed(config, selected) if automatic_preview else selected
            if automatic_preview and not ready:
                result = run(config, selected, False, as_json=args.json, automatic_preview=True, **collection)
            elif len(ready) < len(selected):
                result = apply_and_preview(config, ready, [host for host in selected if host not in ready], args.json, **collection)
            else:
                result = run(config, selected, args.apply, as_json=args.json, **collection)
            return JSON_RUN_EXIT[result] if args.json else result
        if args.command == 'status':
            failed = False
            code = version.describe()
            if code:
                print(f'Code: {code}')
            for host in selected:
                try:
                    usage = disk.measure(host)
                    print(f'{host.name}: {report.usage(usage)}{pressure_note(usage, config)}')
                except Exception as exc:
                    print(f'{host.name}: unavailable ({exc})')
                    failed = True
            paths = report.paths(config['report_dir'])
            print('Last report: ' + (str(paths[-1]) if paths else 'none'))
            for line in report.summarize(paths[-1]) if paths else ():
                print(line)
            return int(failed)
        if args.command == 'find':
            if not args.term:
                return refuse(args, 'coldcleaner: search term is empty')
            records = store.find(args.term, config['nas_root'])
            record_human_action(config, args.command, len(records))
            for record in records:
                print_archive(record)
            if not records:
                print(f'no archives match {args.term!r}')
        elif args.command == 'restore' and args.id.startswith('quarantine:'):
            _, host, ident = args.id.split(':')
            if host not in hosts.HOSTS or args.to_host or args.member:
                raise ValueError('quarantine restore needs the original host and the whole item')
            restored = reclaim.probe(hosts.HOSTS[host], 'quarantine-restore', host_name=host, id=ident, to=args.to)
            record_human_action(config, args.command, 1)
            print(f"restored {args.id} to {host}:{restored['restored']}")
            if restored.get('partial'):
                print('A previous purge was interrupted. The recovered item may be incomplete.', file=sys.stderr)
        elif args.command == 'restore':
            record = store.restore(args.id, config['nas_root'], to=args.to, member=args.member, to_host=args.to_host)
            record_human_action(config, args.command, 1)
            target = args.to if args.to is not None else record.source_path
            suffix = f' (member {args.member})' if args.member is not None else ''
            print(f'restored {record.id} to {record.host}:{target}{suffix}')
        return 0
    except Exception as exc:
        message = f'coldcleaner: {exc}'
        if args.command == 'reclaim' and args.json:
            print(message, file=sys.stderr)
            print(json.dumps(summary([], args.apply, None, version.describe(), 'incomplete', [message]), default=str))
            return 2
        if args.command in ('doctor', 'top') and args.json:
            print(message, file=sys.stderr)
            return json_failure(message, 2)
        return refuse(args, message)
