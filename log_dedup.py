#!/usr/bin/env python3
#=============================================================================
# log_dedup.py - Group repeated log lines into patterns before they go to the AI
#=============================================================================
#
# WHAT IT DOES
# Turns thousands of near-identical log lines into a short list of patterns.
# Each line is normalised into a template: timestamps, [PIDs], numbers, hex
# and long IDs, UUIDs, IPv4/IPv6, MACs, durations, quoted paths that
# contain digits and the name in sshd's "invalid user NAME" are masked, and
# whitespace is collapsed. Lines are counted per (severity, process,
# template). render() writes one entry per pattern
# (count, first/last timestamp, raw example line(s)) sorted by severity and
# then count, cut to a character budget by dropping the lowest-priority
# patterns first, with a header line giving the totals.
#
# USAGE
# python3 log_dedup.py --selftest [--lines N]   self-check, exit 0 = OK
# Otherwise a library module. analyzer.py feeds it, main.py renders it:
#   d = LogDedup(keep_examples=1)
#   d.add('error', 'kernel', raw_line)        # once per matched log line
#   text, info = d.render(max_chars=40000, examples=1, total_lines=N,
#                         window='15m')
#   normalize(line)  -> the template string for one line
#
# REQUIRES
# Python 3.7+ standard library only (re).
#
# SIDE EFFECTS
# None: in memory only, no files, no network. Only --selftest prints.
#
# CAVEATS
# - Masking is heuristic. Messages that differ only in a number or ID are
#   merged (that is the point), digits inside words too (eth0 and eth1,
#   error -36 and -43 end up in one pattern; raise --max-examples to see
#   more variants). An odd token such as "ab:cd:" can be masked as IPv6.
#   Raw example lines are never changed, only the grouping templates.
# - sshd: the guessed name after "invalid user " becomes <USER>, so a
#   brute-force burst is one pattern per message type, not one per name.
#   Only when sshd's wording follows the name; a name with a space in it is
#   left as is. Valid accounts ("Failed password for root") stay visible.
# - Templates are compared on their first 300 characters. Example lines
#   longer than 500 characters are cut ("...") in the rendered text.
# - first/last are the leading timestamps in input order (not sorted), and
#   only for lines that start with an ISO or syslog style timestamp.
# - Memory grows with the number of distinct templates (plus keep_examples
#   raw lines each), not with the number of lines.
#
# EXAMPLES
# python3 log_dedup.py --selftest
#   150,000 synthetic lines (6 message types) -> 6 patterns; checks counts,
#   order, first/last times and the size budget; prints a short report.
#   normalize('Oct  8 10:00:01 web sshd[812]: Failed password from '
#             '10.0.0.7 port 51234 ssh2')
#   -> '<TS> web sshd[<PID>]: Failed password from <IP> port <N> ssh<N>'
#
#-----------------------------------------------------------------------------
# Written 2026-10-08 by Script Wrangler (Claude) for ai_logs (time-dedup.patch).
# Unit-tested on synthetic lines only; UNTESTED against real logs.
# History:
# 2026-10-09 - Script Wrangler: the name in sshd "invalid user NAME" lines
#   is masked as <USER> (one pattern per brute-force burst, not one per
#   guessed name); a saved baseline sees those templates as NEW once.
#=============================================================================
import calendar
import re
import time

# Sort order for severities (anything else goes last)
SEVERITY_RANK = {'critical': 0, 'error': 1, 'warning': 2, 'info': 3}

# How a severity is shown. 'critical' in a pattern key only comes from a macOS
# record with logType fault (collector.MAC_LEVELS; the keyword matching gives
# error/warning/info only), so it is shown as FAULT: a macOS log level, not a
# judgement of how serious it is. Every other severity is shown as before.
LEVEL_LABELS = {'critical': 'FAULT'}


def level_label(severity):
    """'FAULT' for a macOS fault (severity 'critical'), else the severity in upper case."""
    return LEVEL_LABELS.get(severity, str(severity).upper())


def merge_same(rows):
    """Display only: [(display_key, numbers), ...] -> [(display_key, summed numbers, n)].
    Rows whose display key (label, level, process, shortened text, id) is the same
    are merged into one, their numbers summed element-wise, n = how many patterns.
    First-seen order is kept. The patterns themselves stay separate."""
    out, at = [], {}
    for key, nums in rows:
        if key in at:
            r = out[at[key]]
            r[1] = [a + b for a, b in zip(r[1], nums)]
            r[2] += 1
        else:
            at[key] = len(out)
            out.append([key, list(nums), 1])
    return [(k, tuple(n), c) for k, n, c in out]


def patterns_suffix(n):
    """' (N patterns)' after a merged display row, '' for a single pattern."""
    return f" ({n} patterns)" if n > 1 else ''

_MONTH = r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
_H = r'[0-9a-fA-F]'

# (name, regex, replacement). They are combined into ONE regex; at each
# position the first alternative that matches wins, so the order matters.
_MASKS = [
    # sshd's "invalid user NAME": the guessed NAME (can be empty) -> <USER>,
    # only when sshd's wording follows (" from ", " HOST port N", " [preauth]"
    # or the end), and not "from HOST port" itself (empty NAME, spaces
    # collapsed). Valid accounts ("for root from") are kept. First in the
    # list, so a name like 1234 or 10.0.0.1 is <USER>, not <N> or <IP>.
    ('user',  r'(?<=\b[Ii]nvalid user )(?!from\s\S+\sport\s)\S*'
              r'(?=\s(?:from\s|\S+\sport\s\d|\[preauth\])|\s*$)', '<USER>'),
    ('ts',    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?', '<TS>'),
    ('sts',   _MONTH + r'\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?', '<TS>'),
    ('date',  r'\b\d{4}[-/]\d{2}[-/]\d{2}\b', '<DATE>'),
    ('uuid',  r'\b' + _H + r'{8}-' + _H + r'{4}-' + _H + r'{4}-' + _H + r'{4}-' + _H + r'{12}\b', '<UUID>'),
    ('mac',   r'\b(?:' + _H + r'{2}[:-]){5}' + _H + r'{2}\b', '<MAC>'),
    ('time',  r'\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b', '<TIME>'),
    ('path',  r'(?P<q>["\'])~?/[^"\'\n]*?\d[^"\'\n]*?(?P=q)', None),  # keeps the quotes
    ('ipv4',  r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b', '<IP>'),
    ('ipv6',  r'(?<![\w:.])(?=[0-9a-fA-F:]*[0-9a-fA-F])(?:' + _H + r'{0,4}:){2,7}' + _H + r'{0,4}(?![\w:])', '<IPV6>'),
    ('hex',   r'\b0[xX]' + _H + r'+\b', '<HEX>'),
    ('hexid', r'\b(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])' + _H + r'{8,}\b', '<ID>'),
    ('token', r'\b(?=\w*\d)(?=\w*[a-z])(?=\w*[A-Z])\w{16,}\b', '<ID>'),   # random mixed-case IDs
    ('dur',   r'\b\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h|d)\b'
              r'|\b\d+(?:\.\d+)?\s?(?:msecs?|secs?|seconds?|mins?|minutes?|hrs?|hours?|days?)\b', '<DUR>'),
    ('pid',   r'\[\d+\]', '[<PID>]'),
    ('num',   r'\d+(?:\.\d+)?', '<N>'),   # any other digits, also inside words (R123, eth0, 95%)
]
_MASK_RE = re.compile('|'.join('(?P<%s>%s)' % (name, rx) for name, rx, _ in _MASKS))
_REPLACE = {name: rep for name, _, rep in _MASKS}
_SPACES = re.compile(r'\s+')
_LEADING_TS = re.compile(r'\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|'
                         + _MONTH + r'\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')


def _mask(m):
    name = m.lastgroup
    if name == 'path':
        q = m.group('q')
        return q + '<PATH>' + q
    return _REPLACE[name]


def normalize(line):
    """Template used for grouping: variable parts masked, whitespace collapsed."""
    return _SPACES.sub(' ', _MASK_RE.sub(_mask, line)).strip()


def leading_timestamp(line):
    """The ISO or syslog timestamp a line starts with (to the second), or None."""
    m = _LEADING_TS.match(line)
    return m.group(1) if m else None


_TS_ISO = re.compile(r'\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?'
                     r'(Z|[+-]\d{2}:?\d{2})?')
_TS_SYSLOG = re.compile(r'\s*(' + _MONTH + r')\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})')
_MONTH_NO = {m: i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}
_EPOCH_CACHE = {}


def _epoch(key, fields, tz):
    """Seconds since 1970 for (Y, M, D, h, m, s) in zone tz (None = local), cached."""
    t = _EPOCH_CACHE.get(key)
    if t is None:
        y, mo, d, hh, mi, ss = fields
        if not (1 <= mo <= 12 and 1 <= d <= 31 and hh <= 23 and mi <= 59 and ss <= 60):
            return None
        try:
            if tz:
                off = 0 if tz == 'Z' else (int(tz[1:3]) * 60 + int(tz[-2:])) * (-1 if tz[0] == '-' else 1)
                t = calendar.timegm((y, mo, d, hh, mi, ss, 0, 0, 0)) - off * 60
            else:
                t = time.mktime((y, mo, d, hh, mi, ss, 0, 0, -1))
        except (ValueError, OverflowError):
            return None
        if len(_EPOCH_CACHE) > 50000:
            _EPOCH_CACHE.clear()
        _EPOCH_CACHE[key] = t
    return t


def line_epoch(line, now=None):
    """Seconds since 1970 (float) of the time a line starts with, or None.
    ISO times with a zone (Z, +0200, -07:00) are exact; ISO times without
    one and syslog times are taken as local time. Syslog times have no year:
    this year, or the year before if that would be more than a day ahead."""
    m = _TS_ISO.match(line)
    if m:
        g = m.groups()
        t = _epoch(g[:6] + (g[7],), tuple(int(x) for x in g[:6]), g[7])
        return None if t is None else t + (float(g[6]) if g[6] else 0.0)
    m = _TS_SYSLOG.match(line)
    if not m:
        return None
    now = time.time() if now is None else now
    year = time.localtime(now).tm_year
    mon, d, hh, mi, ss = m.groups()
    for y in (year, year - 1):
        fields = (y, _MONTH_NO[mon], int(d), int(hh), int(mi), int(ss))
        t = _epoch(fields, fields, None)
        if t is None or t <= now + 86400:
            return t
    return t


def _label_rank(label):
    """Digest order within one severity: NEW, then SPIKE, then unlabelled."""
    if not label:
        return 2
    return 0 if label.startswith('[NEW') else 1


class LogDedup:
    """Counts lines per (severity, source, template); renders a size-capped digest."""

    KEY_CHARS = 300       # template length used for grouping
    EXAMPLE_CHARS = 500   # longer example lines are cut in render()

    def __init__(self, keep_examples=1):
        self.keep_examples = max(1, int(keep_examples or 1))
        self.patterns = {}   # key -> [count, first_ts, last_ts, [examples]]
        self.times = {}      # key -> each line's time, seconds since 1970 (None = unknown)
        self.lines = 0
        self.mac_levels = False   # True once a line carried a macOS log level (fault/error)

    def add(self, severity, source, line):
        """Record one log line (call once per line, with its highest severity)."""
        epoch = getattr(line, 'epoch', None)   # collector.LogLine: the ndjson record's time
        if getattr(line, 'level', None):
            self.mac_levels = True
        line = line.rstrip('\r\n')
        key = (severity, source or 'unknown', normalize(line)[:self.KEY_CHARS])
        ts = leading_timestamp(line)
        p = self.patterns.get(key)
        if p is None:
            p = self.patterns[key] = [0, ts, ts, []]
            self.times[key] = []
        p[0] += 1
        self.times[key].append(epoch if epoch is not None or not ts else line_epoch(line))
        if ts:
            if p[1] is None:
                p[1] = ts
            p[2] = ts
        if len(p[3]) < self.keep_examples:
            p[3].append(line)
        self.lines += 1

    def ordered(self, labels=None):
        """(key, data) pairs, most important first: severity, then count
        (ties keep first-seen order). With labels (key -> '[NEW]' or
        '[SPIKE xR]', from baseline.py) NEW comes first within each
        severity, then SPIKE, then the rest."""
        labels = labels or {}
        return sorted(self.patterns.items(),
                      key=lambda kv: (SEVERITY_RANK.get(kv[0][0], 9),
                                      _label_rank(labels.get(kv[0])), -kv[1][0]))

    def _entry(self, key, data, examples, label=None):
        severity, source, _ = key
        count, first, last, raw = data
        when = ''
        if first and last and first != last:
            when = f' first {first}, last {last}'
        elif first:
            when = f' at {first}'
        out = [f"{label + ' ' if label else ''}[{level_label(severity)}] {source} x{count}{when}"]
        for line in raw[:examples]:
            if len(line) > self.EXAMPLE_CHARS:
                line = line[:self.EXAMPLE_CHARS] + '...'
            out.append('  ' + line)
        return '\n'.join(out)

    def render(self, max_chars, examples=1, total_lines=None, window=None,
               labels=None, only_labeled=False, note=None):
        """Digest text for the AI prompt, cut to max_chars by dropping the
        lowest-priority patterns first. The header is always kept, so the
        result can only exceed max_chars if max_chars is smaller than the
        header. labels (key -> '[NEW]' / '[SPIKE xR]') go in front of their
        entries and are explained in the header; only_labeled keeps only
        those entries (--ai-changes-only); note (text) ends the header.
        Returns (text, info) with
        lines/patterns/shown/omitted/left_out/chars."""
        items = self.ordered(labels)
        n_all, left_out = len(items), 0
        if only_labeled:
            items = [kv for kv in items if kv[0] in (labels or {})]
            left_out = n_all - len(items)
        entries = [self._entry(k, d, max(1, int(examples or 1)), (labels or {}).get(k))
                   for k, d in items]
        n = len(entries)
        total = self.lines if total_lines is None else total_lines

        # omitted-pattern counts per severity and omitted lines, for any cut point k
        sev_names = []
        for (sev, _, _), _ in items:
            if sev not in sev_names:
                sev_names.append(sev)
        suffix = [dict.fromkeys(sev_names, 0) for _ in range(n + 1)]
        suffix_lines = [0] * (n + 1)
        for i in range(n - 1, -1, -1):
            suffix[i] = dict(suffix[i + 1])
            suffix[i][items[i][0][0]] += 1
            suffix_lines[i] = suffix_lines[i + 1] + items[i][1][0]

        def head(k):
            s = f'=== Log patterns (de-duplicated) ===\n{total} lines'
            if window:
                s += f' (last {window})'
            s += f', {self.lines} matched -> {n_all} patterns'
            if only_labeled:
                s += (f'; only the {n} NEW/SPIKE vs baseline are listed, {left_out} '
                      f'normal pattern(s) left out')
            s += f'; top {k} shown'
            if k < n:
                s += f', {n - k} omitted (size limit)'
            s += ('.\nEach entry: [SEVERITY] process xCOUNT, first/last time, then '
                  'raw example line(s); numbers, IDs, IPs and times vary within a pattern.')
            if self.mac_levels:
                s += ('\n[FAULT] and [ERROR] are macOS log levels (the record\'s logType), not '
                      'severity judgements: a fault is not necessarily serious; judge each '
                      'entry by its content.')
            if labels is not None:
                s += ("\nLabels vs this machine's saved baseline: [NEW] = pattern not seen "
                      "when the baseline was saved; [SPIKE xR] = R times its usual rate per "
                      "minute; no label = normal here.")
            if note:
                s += '\n' + note
            return s

        def foot(k):
            parts = ', '.join(f'{c} {level_label(s).lower()}' for s, c in suffix[k].items() if c)
            return f'[omitted: {parts} pattern(s), {suffix_lines[k]} lines]'

        def size(k):
            body = sum(len(e) + 1 for e in entries[:k])
            return len(head(k)) + body + (len(foot(k)) + 1 if k < n else 0)

        if size(n) <= max_chars:
            k = n
        else:
            k, used = 0, 0
            while k < n - 1:   # grow while the next entry still fits
                used += len(entries[k]) + 1
                if len(head(k + 1)) + used + len(foot(k + 1)) + 1 > max_chars:
                    break
                k += 1
        text = '\n'.join([head(k)] + entries[:k] + ([foot(k)] if k < n else []))
        info = {'lines': self.lines, 'patterns': n_all, 'shown': k,
                'omitted': n - k, 'left_out': left_out, 'chars': len(text)}
        return text, info


# ---------------------------------------------------------------------------
# --selftest: synthetic lines generated in memory (no files, no network)
# ---------------------------------------------------------------------------

def _selftest(n_lines=150000):
    import random
    import time as _time
    rnd = random.Random(229)

    def ip():
        return f"10.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"

    def uuid():
        return '%08x-%04x-%04x-%04x-%012x' % tuple(rnd.getrandbits(b) for b in (32, 16, 16, 16, 48))

    kinds = [  # (weight, severity, process, message)
        (50, 'error', 'kernel', lambda: f"(AppleH13CamIn) ISP_SendCommand error {rnd.randint(1, 9)} addr 0x{rnd.getrandbits(32):x}"),
        (20, 'error', 'sshd', lambda: f"error: PAM: authentication failure for user{rnd.randint(1, 5)} from {ip()} port {rnd.randint(1024, 65535)}"),
        (15, 'warning', 'symptomsd', lambda: f"warning: memory pressure {rnd.randint(50, 99)}% for pid {rnd.randint(100, 99999)}"),
        (8, 'error', 'cloudd', lambda: f"Operation {uuid()} failed with error {rnd.randint(1, 4100)}: CKErrorDomain"),
        (5, 'warning', 'networkd', lambda: f"connection to [fe80::{rnd.getrandbits(16):x}:{rnd.getrandbits(16):x}]:443 slow after {rnd.randint(5, 900)}ms"),
        (2, 'info', 'backupd', lambda: f"INFO: backup job {rnd.randint(1, 99)} done in {rnd.randint(1, 600)}s"),
    ]
    weights = [k[0] for k in kinds]
    t0 = _time.perf_counter()
    expect, seen_ts, raw_chars = {}, {}, 0
    d = LogDedup(keep_examples=1)
    for i in range(n_lines):
        _, sev, proc, msg = rnd.choices(kinds, weights)[0]
        secs = 900 * i // n_lines                      # a 15-minute window
        ts = f"2026-10-08 10:{secs // 60:02d}:{secs % 60:02d}"
        line = f"{ts}.{rnd.randint(0, 999999):06d}-0700  localhost {proc}[{rnd.randint(1, 99999)}]: {msg()}"
        raw_chars += len(line) + 1
        expect[proc] = expect.get(proc, 0) + 1
        seen_ts.setdefault(proc, [ts, ts])[1] = ts
        d.add(sev, proc, line)
    elapsed = _time.perf_counter() - t0

    fails = []

    def check(name, ok, detail=''):
        if not ok:
            fails.append(f"{name} {detail}".strip())

    check('all lines counted', d.lines == n_lines, (d.lines, n_lines))
    check('one pattern per message type', len(d.patterns) == len(kinds), len(d.patterns))
    got = {k[1]: v[0] for k, v in d.patterns.items()}
    check('counts match', got == expect, (got, expect))
    order = [k[0] for k, _ in d.ordered()]
    check('severity order', order == sorted(order, key=lambda s: SEVERITY_RANK[s]), order)
    errs = [v[0] for k, v in d.ordered() if k[0] == 'error']
    check('errors by count', errs == sorted(errs, reverse=True), errs)
    for (sev, proc, _), v in d.patterns.items():
        check(f'first/last {proc}', [v[1], v[2]] == seen_ts[proc], ([v[1], v[2]], seen_ts[proc]))
    text, info = d.render(max_chars=40000, examples=1, total_lines=n_lines, window='15m')
    check('all patterns shown at 40000', info['shown'] == len(kinds) and info['omitted'] == 0, info)
    check('header totals', f"{n_lines} lines (last 15m), {n_lines} matched -> {len(kinds)} patterns" in text)
    small, sinfo = d.render(max_chars=700, examples=1)
    check('budget 700 enforced', len(small) <= 700, len(small))
    check('budget 700 drops lowest priority first',
          0 < sinfo['shown'] < len(kinds) and '[omitted: ' in small and '[ERROR] kernel x' in small, sinfo)
    tiny, tinfo = d.render(max_chars=50)
    check('budget below header: header only', tinfo['shown'] == 0, tinfo)
    samples = [
        ('Oct  8 10:00:01 web sshd[812]: Failed password from 10.0.0.7 port 51234 ssh2',
         '<TS> web sshd[<PID>]: Failed password from <IP> port <N> ssh<N>'),
        ('bluetoothd[99]: LE connection failed for device a4:83:e7:12:9b:0c reason 62',
         'bluetoothd[<PID>]: LE connection failed for device <MAC> reason <N>'),
        ('trustd[5]: cache miss at "/private/var/db/1234/cache.db" cert 3f9a0c77e1b2',
         'trustd[<PID>]: cache miss at "<PATH>" cert <ID>'),
        ('sshd-session[9]: Failed password for invalid user user1 from 10.0.0.7 port 51234 ssh2',
         'sshd-session[<PID>]: Failed password for invalid user <USER> from <IP> port <N> ssh<N>'),
        ('sshd-session[9]: Connection closed by invalid user  10.0.0.7 port 51234 [preauth]',
         'sshd-session[<PID>]: Connection closed by invalid user <USER> <IP> port <N> [preauth]'),
        ('sshd[9]: Failed password for root from 10.0.0.7 port 51234 ssh2',
         'sshd[<PID>]: Failed password for root from <IP> port <N> ssh<N>'),
    ]
    for raw, want in samples:
        check('normalize ' + raw[:24], normalize(raw) == want, normalize(raw))

    print(f"log_dedup selftest: {n_lines:,} synthetic lines -> {len(d.patterns)} patterns "
          f"(expected {len(kinds)}) in {elapsed:.1f}s")
    print(f"  chars: {raw_chars:,} raw lines -> {info['chars']:,} digest "
          f"({raw_chars // max(info['chars'], 1):,}x smaller)")
    print(f"  budget 700: {sinfo['chars']} chars, {sinfo['shown']} shown, {sinfo['omitted']} omitted")
    for name in fails:
        print('  FAIL ' + name)
    print('  result: ' + ('OK' if not fails else f'{len(fails)} check(s) FAILED'))
    return 0 if not fails else 1


if __name__ == '__main__':
    import argparse
    import sys
    ap = argparse.ArgumentParser(description='log_dedup.py: library for ai_logs; '
                                             '--selftest checks it on synthetic lines.')
    ap.add_argument('--selftest', action='store_true', help='run the self-check (exit 0 = OK)')
    ap.add_argument('--lines', type=int, default=150000, help='synthetic lines for --selftest (default 150000)')
    a = ap.parse_args()
    if not a.selftest:
        ap.print_help()
        sys.exit(2)
    sys.exit(_selftest(max(1000, a.lines)))
