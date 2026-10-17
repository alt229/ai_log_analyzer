#=============================================================================
# platforms/darwin.py - macOS: unified log via `log show --style ndjson`
#=============================================================================
#
# WHAT IT DOES
# Reads macOS's unified log for a time window and turns each ndjson record
# into one LogLine in the syslog shape the analyzer expects ("TIMESTAMP
# localhost proc[PID]: (sender) [subsystem:category] message"), with the
# record's real level, process, subsystem and time attached.
# Local (--local on a Mac): `log show --start <time>` as a child process;
# its own pid and ours are dropped from the result. Remote (--host on a
# Mac, new with platforms.patch): the same over SSH with `--last Ns`, so
# the Mac's own clock decides the window; only the `log` tool's note about
# the run is dropped (the remote pids are unknown).
# Default: logType error + fault only; --all-levels: the old keyword
# predicate. Noise filters that fit become AND NOT (...) in the predicate.
#
# Moved here from collector.py unchanged (MAC_* predicates, LogLine,
# parse_macos_ndjson); collector.py still exports those names.
# Written 2026-10-10 by Script Wrangler (Claude) for ai_logs (platforms.patch).
# History:
# 2026-10-10 - Script Wrangler: first version (moved from collector.py,
#   plus the remote command).
#=============================================================================
import json
import os
import shlex
import subprocess
from datetime import datetime

NAME = 'darwin'
TOOL = 'log show'

# macOS `log show` predicates. Default: only real errors and faults (field
# `logType`, as listed by `log help predicates`). --all-levels: the old
# keyword filter, which also catches ordinary messages that merely mention
# "error", "warning", "failed" etc.
MAC_LEVEL_PREDICATE = '(logType == "error" OR logType == "fault")'
MAC_KEYWORD_PREDICATE = '(eventMessage CONTAINS[c] "error" OR eventMessage CONTAINS[c] "warning" OR eventMessage CONTAINS[c] "failure" OR eventMessage CONTAINS[c] "failed" OR process == "system")'
# macOS log type -> analyzer/dedup severity (other types: decided by keywords)
MAC_LEVELS = {'fault': 'critical', 'error': 'error'}


class LogLine(str):
    """A log line (a normal str) plus fields from `log show --style ndjson`:
    process = full process name (may contain spaces), level = 'critical'
    (fault), 'error' or None, subsystem (or None) and message (the event
    message alone; noise_filters.py matches on these), epoch (the record's
    time in seconds since 1970, None if unparseable) and pid (processID).
    Lines from SSH, Linux and Docker are plain str."""
    def __new__(cls, text, process=None, level=None, subsystem=None, message=None,
                epoch=None, pid=None):
        self = super().__new__(cls, text)
        self.process = process
        self.level = level
        self.subsystem = subsystem
        self.message = message
        self.epoch = epoch
        self.pid = pid
        return self


def _is_own_log_show(process, message):
    """The `log` process's note about a `log show` run, like ours (it repeats
    our predicate, so it matched "error"). Only that kind of `log` line."""
    return (process == 'log' and 'log run noninteractively' in message
            and "'log' 'show'" in message)


def parse_macos_ndjson(text, drop_pids=(), stats=None):
    """`log show --style ndjson` output -> list of LogLine in the syslog shape
    "TIMESTAMP  localhost proc[PID]: (sender) [subsystem:category] message".
    One JSON object per line. A line that is not a JSON object is kept as
    plain text, so nothing is lost if the format changes. Records whose
    processID is in drop_pids (this tool and its `log` child) are dropped
    and counted in stats['own']."""
    from log_dedup import line_epoch
    out = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        rec = None
        if raw.lstrip().startswith('{'):
            try:
                rec = json.loads(raw)
            except ValueError:
                rec = None
        if not isinstance(rec, dict):
            if not (' log[' in raw and _is_own_log_show('log', raw)):
                out.append(raw)
            continue
        msg = str(rec.get('eventMessage') or rec.get('composedMessage') or rec.get('message') or '')
        msg = ' '.join(msg.splitlines())   # one record = one line
        proc = str(rec.get('process') or os.path.basename(str(rec.get('processImagePath') or ''))
                   or 'unknown')
        if _is_own_log_show(proc, msg):
            continue
        pid = next((rec[k] for k in ('processID', 'processIdentifier') if rec.get(k) is not None), 0)
        if drop_pids and pid in drop_pids:   # exact pid match: our own process or our `log show`
            if stats is not None:
                stats['own'] = stats.get('own', 0) + 1
            continue
        sender = rec.get('sender') or os.path.basename(str(rec.get('senderImagePath') or ''))
        sub, cat = rec.get('subsystem') or '', rec.get('category') or ''
        kind = str(rec.get('messageType') or rec.get('logType') or '').lower()
        ts = rec.get('timestamp') or rec.get('date') or ''
        line = f"{ts}  localhost {proc}[{pid}]:"
        if sender:
            line += f" ({sender})"
        if sub or cat:
            line += f" [{sub}:{cat}]"
        out.append(LogLine(f"{line} {msg}", process=proc, level=MAC_LEVELS.get(kind),
                           subsystem=str(sub) if sub else None, message=msg,
                           epoch=line_epoch(str(ts)) if ts else None, pid=pid))
    return out


def predicate(collector):
    """The log show predicate for collector.mac_levels, plus AND NOT (...) for
    collector.noise_filters that fit (sets collector.noise_at_source)."""
    pred = MAC_KEYWORD_PREDICATE if collector.mac_levels == 'all' else MAC_LEVEL_PREDICATE
    if collector.noise_filters:   # known noise: AND NOT (...), so log show never returns it
        from noise_filters import mac_exclusions
        extra, collector.noise_at_source = mac_exclusions(collector.noise_filters)
        pred += extra
    return pred


def local_logs(collector, since):
    """Local macOS logs since `since` ('%Y-%m-%d %H:%M:%S') as LogLine objects
    (ndjson gives the real log level and full process names, which syslog
    style does not)."""
    macos_time = datetime.strptime(since, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
    cmd = [
        'log', 'show',
        '--start', macos_time,
        '--style', 'ndjson',   # one JSON object per line (json = one big array)
        '--predicate', predicate(collector)
    ]
    # Popen instead of run(): the child's pid lets us drop its own log lines
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          encoding='utf-8', errors='replace') as proc:
        stdout, stderr = proc.communicate()
    collector._check_result('log show', proc.returncode, stdout, stderr)
    stats = {}
    lines = parse_macos_ndjson(stdout, drop_pids={os.getpid(), proc.pid}, stats=stats)
    collector.own_lines_dropped = stats.get('own', 0)
    return lines


def remote_cmd(collector, seconds):
    """Shell command for the last `seconds` seconds on a remote Mac."""
    return (f"log show --last {int(seconds)}s --style ndjson "
            f"--predicate {shlex.quote(predicate(collector))}")


def parse(collector, text):
    return parse_macos_ndjson(text)
