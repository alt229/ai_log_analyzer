#!/usr/bin/env python3
#=============================================================================
# noise_filters.py - Known-noise filters for ai_logs (per-machine noise.yaml)
#=============================================================================
#
# WHAT IT DOES
# Reads ~/.local/share/ai_logs/<target>/noise.yaml (or --noise-file), checks
# each entry, and drops log lines that match one. An entry has any of
# process, subsystem, message, plus optional source (docker or system) and
# note; all fields given must match. process and subsystem are exact,
# case-sensitive names; message is a case-insensitive substring. On macOS
# --local the filters also become `AND NOT (...)` clauses of the
# `log show --predicate`, so that noise is never fetched. It can also turn
# a run's top patterns into ready-to-paste YAML (--suggest-noise) and, only
# for the numbers you name, append them to noise.yaml (--write-noise).
#
# USAGE
# Library module for main.py and collector.py:
#   filters, warnings, state = load_noise_file(path)  # state ok/missing/error
#   extra, n = mac_exclusions(filters)     # ' AND NOT (...)...', count used
#   stats = NoiseStats(filters); kept = apply_filters(lines, stats)
#   text, entries = suggest(dedup, 10, path, window='5m')
#   added, dups = append_entries(path, [entries[0]])
#
# noise.yaml is a plain YAML list (the form --write-noise appends to):
#   - process: "WindowServer"
#     message: "Invalid window"
#     note: "redraw noise, checked 2026-10-09"
# A mapping with one key, noise_filters: [...], is read too.
#
# REQUIRES
# Python 3.7+; PyYAML (alt229-dev venv, as config.py) to read/append
# noise.yaml; log_dedup.py and target_store.py next to it.
#
# SIDE EFFECTS
# Only append_entries() writes: noise.yaml via temp file + rename (mode
# 600, folder 700), existing text kept byte for byte. Nothing is deleted.
#
# CAVEATS
# - A dropped line is gone from the report, the AI digest and the baseline.
#   A broad entry (process: kernel alone) hides real problems;
#   --no-noise-filter turns the file off for one run.
# - Text lines (Linux, SSH, Docker) have no subsystem, so an entry with
#   subsystem never matches them, and message is matched against the whole
#   line. Docker lines usually have no process name at all: use message.
# - macOS: lines excluded in the log show predicate are not counted.
#   Multi-line messages are joined with spaces after collection, so a
#   message that spans a line break only matches after collection.
#
#-----------------------------------------------------------------------------
# Written 2026-10-09 by Script Wrangler (Claude) for ai_logs
# (noise-baseline.patch). Unit-tested on synthetic data only; UNTESTED
# against real logs and a real `log show`.
# History:
# 2026-10-09 - Script Wrangler: Linux process names containing - . / @
#   (sshd-session, systemd-logind, postfix/smtpd) are read whole instead of
#   becoming 'unknown', in step with analyzer.py, so process: entries match.
#=============================================================================
import hashlib
import json
import os
import re
import time

from log_dedup import normalize, level_label
import target_store

FIELDS = ('process', 'subsystem', 'message')
ALLOWED_KEYS = FIELDS + ('source', 'note')
SOURCES = ('system', 'docker')   # system = log show / journalctl lines
MAX_SOURCE_FILTERS = 100         # more than this: the rest only after collection
MAX_PREDICATE_CHARS = 20000      # the same, by predicate size
# Predicate fields. process and subsystem are in `log help predicates`. The
# message field is the one the old keyword predicate uses (it worked on
# Erin's Mac); `log help predicates` on macOS 26 lists composedMessage
# instead. If log show ever rejects eventMessage, change it here.
MAC_FIELDS = {'process': 'process', 'subsystem': 'subsystem', 'message': 'eventMessage'}

# Same process name as analyzer.py's analyze_line() (keep them in step)
MAC_SYSLOG_PROC = re.compile(
    r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[-+]\d{4}\s+\S+\s+(\S[^\[\]]*?)\[\d+\]:')
# Linux "ident[pid]:"; ident may have - . / @ (sshd-session, postfix/smtpd)
_PLAIN_PROC = re.compile(r'\s([\w./@-]+)\[\d+\]:')
# After "proc[pid]:" in the macOS shape: (sender) [subsystem:category] message
_MAC_REST = re.compile(r' (?:\(([^()]*)\) )?(?:\[([^\[\]:]*):([^\[\]]*)\] )?(.*)$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_MASKED_PART = re.compile(r'<[A-Z0-9]+>')
_TRIM = ' \t"\'[](){}<>:;,=|'


class NoiseFilter:
    """One noise.yaml entry. index = its position in the file (1-based)."""

    def __init__(self, index, process=None, subsystem=None, message=None,
                 source=None, note=None):
        self.index, self.note, self.source = index, note, source
        self.process, self.subsystem, self.message = process, subsystem, message
        self._message_l = message.lower() if message is not None else None

    def applies_to(self, kind):
        return self.source is None or self.source == kind

    def matches(self, process, subsystem, text_l):
        return ((self.process is None or process == self.process)
                and (self.subsystem is None or subsystem == self.subsystem)
                and (self._message_l is None or self._message_l in text_l))

    def describe(self):
        parts = [f'{k}={json.dumps(getattr(self, k), ensure_ascii=False)}'
                 for k in FIELDS if getattr(self, k) is not None]
        s = f'#{self.index} ' + ' AND '.join(parts)
        if self.source:
            s += f' (source {self.source})'
        return s + (f'  - {self.note}' if self.note else '')


def parse_filters(raw, label='noise.yaml'):
    """Entries -> (list of NoiseFilter, list of warnings). Never raises: a
    bad entry (unknown key, empty, wrong type) is skipped with a warning."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], [f"{label}: expected a list of entries (- process: ...), got "
                    f"{type(raw).__name__}; no noise filters used"]
    filters, warnings = [], []
    for i, entry in enumerate(raw, 1):
        where = f"{label} entry {i} skipped"
        if not isinstance(entry, dict) or not entry:
            warnings.append(f"{where}: {'empty entry' if not entry else 'not a key: value entry'}")
            continue
        unknown = sorted(str(k) for k in entry if k not in ALLOWED_KEYS)
        if unknown:
            warnings.append(f"{where}: unknown key(s) {', '.join(unknown)} "
                            f"(allowed: {', '.join(ALLOWED_KEYS)})")
            continue
        vals, bad = {}, None
        for k in ALLOWED_KEYS:
            v = entry.get(k)
            if v is None:
                continue
            if isinstance(v, bool) or not isinstance(v, (str, int, float)):
                bad = f"{k} must be text"
            elif k != 'note' and not str(v).strip():
                bad = f"{k} is empty"
            elif k != 'note' and _CONTROL.search(str(v)):
                bad = f"{k} contains a control character (newline, tab, ...)"
            elif k == 'source' and str(v) not in SOURCES:
                bad = f"source must be one of {', '.join(SOURCES)}"
            if bad:
                break
            vals[k] = str(v)
        if bad:
            warnings.append(f"{where}: {bad}")
        elif not any(k in vals for k in FIELDS):
            warnings.append(f"{where}: needs at least one of process, subsystem, message")
        else:
            filters.append(NoiseFilter(i, **vals))
    return filters, warnings


def load_noise_file(path):
    """(filters, warnings, state) with state 'ok', 'missing' or 'error'.
    Never raises; a broken file means no filters (and a warning)."""
    if not os.path.exists(path):
        return [], [], 'missing'
    try:
        import yaml
        with open(path, encoding='utf-8') as fh:
            raw = yaml.safe_load(fh)
    except Exception as e:
        return [], [f"{path} could not be read ({e}); no noise filters used this run"], 'error'
    warnings = []
    if isinstance(raw, dict) and 'noise_filters' in raw:
        extra = sorted(str(k) for k in raw if k != 'noise_filters')
        if extra:
            warnings.append(f"{path}: top-level key(s) ignored: {', '.join(extra)}")
        raw = raw['noise_filters']
    filters, more = parse_filters(raw, os.path.basename(path))
    return filters, warnings + more, 'ok'


# --- macOS log show predicate ----------------------------------------------

def predicate_quote(text):
    """NSPredicate string literal: backslash and double quote escaped."""
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def predicate_clause(f):
    parts = []
    if f.process is not None:
        parts.append(f"{MAC_FIELDS['process']} == {predicate_quote(f.process)}")
    if f.subsystem is not None:
        parts.append(f"{MAC_FIELDS['subsystem']} == {predicate_quote(f.subsystem)}")
    if f.message is not None:
        parts.append(f"{MAC_FIELDS['message']} CONTAINS[c] {predicate_quote(f.message)}")
    return ' AND '.join(parts)


def mac_exclusions(filters, max_filters=MAX_SOURCE_FILTERS, max_chars=MAX_PREDICATE_CHARS):
    """' AND NOT (...)' for the first system filters (at most max_filters and
    max_chars). Returns (text, number used). The caller still applies every
    filter after collection (safety net, and for the ones left over)."""
    out, used = '', 0
    for f in [f for f in filters if f.applies_to('system')][:max_filters]:
        clause = f' AND NOT ({predicate_clause(f)})'
        if len(out) + len(clause) > max_chars:
            break
        out += clause
        used += 1
    return out, used


# --- matching after collection ----------------------------------------------

def split_mac_line(line):
    """(process, sender, subsystem, message) of a macOS syslog-shaped line, or None."""
    m = MAC_SYSLOG_PROC.match(line)
    if not m:
        return None
    r = _MAC_REST.match(line, m.end())
    if not r:
        return m.group(1), None, None, line[m.end():].strip()
    return m.group(1), r.group(1), r.group(2) or None, r.group(4)


def line_fields(line):
    """(process, subsystem, text for message matching), as the filters see a line."""
    process = getattr(line, 'process', None)
    message = getattr(line, 'message', None)
    if process and message is not None:          # macOS ndjson (collector.LogLine)
        return process, getattr(line, 'subsystem', None) or None, message
    parts = split_mac_line(line)
    if parts:
        return process or parts[0], parts[2], line
    m = _PLAIN_PROC.search(line)
    return process or (m.group(1) if m else 'unknown'), None, line


class NoiseStats:
    """Filters in use plus what they skipped after collection."""

    def __init__(self, filters, at_source=0):
        self.filters = list(filters)
        self.at_source = at_source               # set from collector.noise_at_source
        self.counts = {f.index: 0 for f in self.filters}
        self.skipped = 0

    def summary(self):
        n, m = self.skipped, len(self.filters)
        s = (f"{n:,} line{'' if n == 1 else 's'} skipped by {m} noise "
             f"filter{'' if m == 1 else 's'}")
        if self.at_source:
            s += (" (macOS: filtered at source, not counted)" if self.at_source >= m else
                  f" (macOS: the first {self.at_source} filtered at source, not counted)")
        return s

    def report(self):
        """--show-noise text: every filter with its post-collection count."""
        out = [f"=== Noise filters: {self.summary()} ==="]
        src = self.source_side()
        for f in sorted(self.filters, key=lambda f: (-self.counts[f.index], f.index)):
            c = self.counts[f.index]
            extra = ' (+ applied in log show, not counted)' if f.index in src else ''
            out.append(f"  {c:>7,} after collection{extra}  {f.describe()}")
        return '\n'.join(out)

    def source_side(self):
        """Indexes of the filters that went into the macOS log show predicate."""
        return {f.index for f in [f for f in self.filters if f.applies_to('system')][:self.at_source]}

    def brief(self):
        """--report-noise lines: each filter and what it matched this run."""
        src, out = self.source_side(), []
        for f in sorted(self.filters, key=lambda f: (f.index not in src, -self.counts[f.index], f.index)):
            c = self.counts[f.index]
            what = (('at source, not counted' + (f' +{c:,} after' if c else '')) if f.index in src
                    else f'{c:,} matched')
            out.append(f"  {what:>22}  {f.describe()}")
        return out


def apply_filters(lines, stats, kind='system'):
    """lines without the ones a filter matches; counts go to stats (each
    line once, for the first matching entry in file order)."""
    active = [f for f in stats.filters if f.applies_to(kind)]
    if not active:
        return list(lines)
    by_proc, generic = {}, []
    for f in active:
        (by_proc.setdefault(f.process, []) if f.process is not None else generic).append(f)
    need_text = any(f.message is not None for f in active)
    kept = []
    for line in lines:
        process, subsystem, text = line_fields(line)
        text_l = text.lower() if need_text else ''
        hit = next((f for f in by_proc.get(process, ()) if f.matches(process, subsystem, text_l)), None)
        for f in generic:
            if hit is not None and f.index > hit.index:
                break
            if f.matches(process, subsystem, text_l):
                hit = f
                break
        if hit is None:
            kept.append(line)
        else:
            stats.counts[hit.index] += 1
            stats.skipped += 1
    return kept


# --- --suggest-noise / --write-noise -----------------------------------------

def literal_run(message, max_len=60, min_len=4):
    """Longest unmasked literal run of the message's dedup template that is
    also really in the message (any case), cut to about max_len, or None."""
    raw_l = message.lower()
    runs = [r.strip(_TRIM) for r in _MASKED_PART.split(normalize(message))]
    for r in sorted(runs, key=len, reverse=True):
        if len(r) < min_len:
            break
        if r.lower() not in raw_l or _CONTROL.search(r):
            continue
        if len(r) > max_len:
            cut = r[:max_len]
            sp = cut.rfind(' ')
            r = (cut[:sp] if sp >= max_len // 2 else cut).strip(_TRIM)
        return r
    return None


def _yaml_str(v):
    return json.dumps(v, ensure_ascii=False)   # a JSON string is a YAML double-quoted scalar


def entry_yaml(e, indent=''):
    lines = []
    for k in ALLOWED_KEYS:
        if e.get(k) is not None:
            lines.append(f"{indent}{'- ' if not lines else '  '}{k}: {_yaml_str(e[k])}")
    return '\n'.join(lines) + '\n'


def entry_id(e):
    """6 hex chars from process/subsystem/message/source (not the note), so
    the same suggestion has the same id in every run."""
    key = json.dumps([e.get(k) for k in ('process', 'subsystem', 'message', 'source')])
    return hashlib.sha1(key.encode('utf-8')).hexdigest()[:6]


def _suggestion(proc, examples):
    """(entry without note, example line, writable?) for one dedup pattern."""
    example = _CONTROL.sub(' ', examples[0] if examples else '')
    parts = split_mac_line(example)
    subsystem = parts[2] if parts else None
    message = parts[3] if parts else example.split(']: ', 1)[-1]
    lit = literal_run(message)
    e = {}
    if proc and proc != 'unknown':
        e['process'] = proc
    if subsystem:
        e['subsystem'] = subsystem
    if lit:
        e['message'] = lit
    return e, example, bool(lit) and any(k in e for k in FIELDS)


def suggestion_groups(dedup):
    """Every pattern as a suggestion; patterns that give the same process,
    subsystem and message are merged (counts summed). Biggest first. Each
    group: entry, id, count, severities, example, writable, keys."""
    groups = {}
    for key, (count, _first, _last, examples) in sorted(dedup.patterns.items(),
                                                        key=lambda kv: -kv[1][0]):
        e, example, writable = _suggestion(key[1], examples)
        ident = tuple(e.get(k) for k in FIELDS)
        g = groups.get(ident)
        if g is None:
            groups[ident] = {'entry': e, 'id': entry_id(e), 'count': count, 'severities': [key[0]],
                             'example': example, 'writable': writable, 'keys': [key]}
            continue
        g['count'] += count
        g['keys'].append(key)
        if key[0] not in g['severities']:
            g['severities'].append(key[0])
    return sorted(groups.values(), key=lambda g: -g['count'])


def _levels(g):
    """'fault/error' etc.: the group's log levels as shown in the report, lower case."""
    return '/'.join(level_label(s).lower() for s in g['severities'])


def _with_note(g, window):
    return dict(g['entry'], note=f"x{g['count']} in {window or '?'} ({_levels(g)}); "
                                 f"inferred benign? check it")


def suggest(dedup, n, path, window=None, target=None):
    """(text, entries, by_id) for --suggest-noise: the top n suggestions by
    count (identical process/subsystem/message merged, counts summed) as
    noise.yaml entries. entries[i] is suggestion i+1 (None = not writable);
    by_id = {id: [entry, ...]} for every writable suggestion of this run
    (more than one entry = two suggestions share an id)."""
    groups = suggestion_groups(dedup)
    items = groups[:n]
    where = f"{target}, " if target else ''
    out = [f"# === Noise filter suggestions: top {len(items)} patterns ({where}last {window or '?'}) ===",
           "# Nothing was written. To use some, paste them at the end of",
           f"#   {path}",
           "# (a YAML list: each entry starts with '- ' at the start of a line;",
           "# the file is created by you, chmod 600 it), or re-run with",
           "# --suggest-noise --write-noise ID,ID (the 6-character ids stay the same",
           "# from run to run; plain numbers refer to the list of that same run).",
           "# Check each one first: a filtered line never reaches the report, the",
           "# AI or the baseline. process/subsystem = exact name, message = text",
           "# anywhere in the message, any case. Add  source: \"docker\"  to limit an",
           "# entry to Docker lines (or \"system\" for the system log only).",
           '']
    entries = []
    for i, g in enumerate(items, 1):
        e, example = _with_note(g, window), g['example']
        short = example if len(example) <= 160 else example[:157] + '...'
        merged = f" ({len(g['keys'])} patterns merged)" if len(g['keys']) > 1 else ''
        out.append(f"# [{i}] id {g['id']}  {_levels(g)} x{g['count']}{merged}, "
                   f"e.g.: {short}")
        if not g['writable']:
            entries.append(None)
            out.append("# no stable message text: this entry would hide EVERY line of the")
            out.append("# process/subsystem, so it is commented out and --write-noise skips it")
            out.append(''.join('# ' + ln + '\n' for ln in entry_yaml(e).splitlines()).rstrip('\n'))
        else:
            entries.append(e)
            out.append(entry_yaml(e).rstrip('\n'))
    if not items:
        out.append('# (no patterns in this run)')
    by_id = {}
    for g in groups:
        if g['writable']:
            by_id.setdefault(g['id'], []).append(_with_note(g, window))
    return '\n'.join(out), entries, by_id


def _ident(e):
    msg = e.get('message')
    return (e.get('process'), e.get('subsystem'), msg.lower() if isinstance(msg, str) else msg,
            e.get('source'))


def append_entries(path, entries):
    """Append entries (dicts) to noise.yaml, keeping the existing text as it
    is and skipping duplicates (same process/subsystem/message/source).
    Atomic (temp + rename). Returns (number added, list of duplicates).
    Raises RuntimeError and writes nothing if the result would not parse as
    the old entries plus the new ones."""
    import yaml
    old_text, old = '', []
    if os.path.exists(path):
        with open(path, encoding='utf-8') as fh:
            old_text = fh.read()
        try:
            old = yaml.safe_load(old_text) if old_text.strip() else []
        except yaml.YAMLError as e:
            raise RuntimeError(f"{path} does not parse ({e}); not changed") from e
        old = [] if old is None else old
        if not isinstance(old, list):
            raise RuntimeError(f"{path} is not a plain YAML list ('- process: ...' at the "
                               f"top level); not changed. Paste the entries by hand.")
    seen = {_ident(e) for e in old if isinstance(e, dict)}
    add, dups = [], []
    for e in entries:
        (dups if _ident(e) in seen else add).append(e)
        seen.add(_ident(e))
    if not add:
        return 0, dups
    text = old_text or "# ai_logs noise filters: a YAML list, see README.md\n"
    if not text.endswith('\n'):
        text += '\n'
    text += (f"# added {time.strftime('%Y-%m-%d %H:%M:%S')} by --write-noise\n"
             + ''.join(entry_yaml(e) for e in add))
    if yaml.safe_load(text) != old + add:
        raise RuntimeError(f"appending to {path} would not give the expected entries "
                           f"(unusual file layout?); not changed. Paste by hand.")
    target_store.atomic_write(path, text)
    return len(add), dups
