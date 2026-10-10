#!/usr/bin/env python3
#=============================================================================
# baseline.py - "What is normal for this machine" for ai_logs (NEW / SPIKE)
#=============================================================================
#
# WHAT IT DOES
# --save-baseline stores a run's log patterns (the de-duplicated, masked
# templates from log_dedup.py) in ~/.local/share/ai_logs/<target>/
# baseline.json (baseline-docker.json for runs with --docker). Each
# pattern's lines are counted in fixed time buckets (default 60 min,
# --baseline-bucket) from the start of the run's window: the busiest
# bucket gives its peak rate per minute, stored next to the average (mean)
# rate. Later runs compare against it: a pattern that is not in the
# baseline is NEW; one whose peak rate (bucketed the same way) is >=
# --spike-factor times the baseline peak rate (and has >= --spike-min
# lines) is SPIKE. --spike-vs mean compares the average rates instead (the
# old behaviour). main.py shows the labels in the report and the AI digest,
# and --ai-changes-only sends only those patterns to the AI.
#
# USAGE
# Library module for main.py:
#   base, err = load_baseline(path)          # (None, None) = none yet
#   labels = compare(dedup, base, minutes, 5.0, 5, vs='peak', start=t0)
#   msg = save_baseline(path, dedup, target, kind, minutes, replace=False,
#                       bucket_minutes=None, start=t0, end=t1)
#   minutes = overlap_minutes(base, t0, t1)  # run window vs saved window
#   print(info_text(path)[0])
#
# REQUIRES
# Python 3.7+ standard library; log_dedup.py and target_store.py.
#
# SIDE EFFECTS
# save_baseline() writes the baseline file (mode 600, folder 700) through
# a temp file and os.replace. Nothing is ever deleted.
#
# CAVEATS
# - Templates are masked (numbers, IDs, IPs, paths with digits), but can
#   still hold host names, user names and paths: keep the files private.
# - Patterns are matched on (severity, process, template). A change in the
#   masking rules or a macOS update can make many patterns NEW once; save
#   again with --replace-baseline at a quiet time.
# - Peak rate = most lines in one bucket / bucket minutes. Buckets start at
#   the window start (run time minus -t). A window shorter than one bucket,
#   or a pattern without any timed line, uses its average rate instead.
#   Lines without a parseable time count toward count, not toward the peak.
# - Merging keeps the highest peak and mean rate ever saved per pattern and
#   sums the counts, so a baseline saved during an incident hides later
#   spikes of that pattern. buckets_seen adds up for windows that don't
#   overlap; for overlapping ones it keeps the larger (a lower bound).
# - Format 1 files (before peak rates) are read with peak = mean, and those
#   patterns are compared mean against mean as before, until you save again
#   with --replace-baseline (OLD_FORMAT_HINT is printed).
#
#-----------------------------------------------------------------------------
# Written 2026-10-09 by Script Wrangler (Claude) for ai_logs
# (noise-baseline.patch); peak rates added by peak-quiet.patch. Unit-tested
# on synthetic data only.
#=============================================================================
import json
import os
import re
import time

from log_dedup import normalize, SEVERITY_RANK, level_label, merge_same, patterns_suffix
import target_store

FORMAT = 2
DEFAULT_BUCKET = 60   # minutes
OLD_FORMAT_HINT = 'old baseline format: rebuild with --replace-baseline for peak rates'
NOTE = ('ai_logs baseline: masked log templates per pattern. They can still contain '
        'host names and paths: keep this file private (mode 600).')


def baseline_file(target, docker=False):
    name = 'baseline-docker.json' if docker else 'baseline.json'
    return os.path.join(target_store.target_dir(target), name)


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and x == x and x >= 0


def load_baseline(path):
    """(data, error). data = file dict with 'patterns' as {key: record};
    (None, None) if there is no file; (None, message) if it is unusable.
    Every record has mean_rate and peak_rate_per_min; format-1 records get
    peak = mean and peak_is_mean = True (counted in data['old_format'])."""
    if not os.path.exists(path):
        return None, None
    try:
        with open(path, encoding='utf-8') as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        return None, f"cannot read it ({e})"
    if not isinstance(doc, dict) or not isinstance(doc.get('patterns'), list):
        return None, "not an ai_logs baseline (no 'patterns' list)"
    pats, bad, old = {}, 0, 0
    for p in doc['patterns']:
        mean = p.get('mean_rate', p.get('rate_per_min')) if isinstance(p, dict) else None
        if not (isinstance(p, dict) and all(isinstance(p.get(k), str) for k in ('severity', 'process', 'template'))
                and _num(mean) and _num(p.get('count', 0))):
            bad += 1
            continue
        p = dict(p, mean_rate=mean)
        if p.get('peak_is_mean') or not _num(p.get('peak_rate_per_min')):
            p['peak_rate_per_min'], p['peak_is_mean'] = mean, True
            old += 1
        pats[(p['severity'], p['process'], p['template'])] = p
    bucket = doc.get('bucket_minutes')
    start, end = doc.get('window_start'), doc.get('window_end')
    window_ok = _num(start) and _num(end) and end >= start
    doc = dict(doc, patterns=pats, bad_entries=bad, old_format=old,
               bucket_minutes=bucket if _num(bucket) and bucket > 0 else None,
               window_start=start if window_ok else None, window_end=end if window_ok else None)
    return doc, None


def _rate(count, minutes):
    return float(f'{count / max(minutes, 1e-9):.6g}')


def bucket_counts(times, start, bucket_minutes):
    """({bucket number: lines}, lines without a time). Bucket 0 starts at
    start (seconds since 1970; None = at 1970) and lasts bucket_minutes."""
    size, origin = bucket_minutes * 60.0, start or 0.0
    counts, unknown = {}, 0
    for t in times:
        if t is None:
            unknown += 1
            continue
        i = int((t - origin) // size)
        counts[i] = counts.get(i, 0) + 1
    return counts, unknown


def peak_rate(count, counts, minutes, bucket_minutes):
    """Lines per minute in the busiest bucket, or the average over the window
    if that is shorter than one bucket or no line had a time."""
    if minutes < bucket_minutes or not counts:
        return count / max(minutes, 1e-9)
    return max(counts.values()) / bucket_minutes


def snapshot(dedup, minutes, now, bucket_minutes, start):
    out, times = {}, getattr(dedup, 'times', {})
    for key, d in dedup.patterns.items():
        counts, unknown = bucket_counts(times.get(key, ()), start, bucket_minutes)
        mean = _rate(d[0], minutes)
        rec = {'severity': key[0], 'process': key[1], 'template': key[2], 'count': d[0],
               'buckets_seen': len(counts), 'peak_count': max(counts.values()) if counts else 0,
               'peak_rate_per_min': float(f'{peak_rate(d[0], counts, minutes, bucket_minutes):.6g}'),
               'mean_rate': mean, 'rate_per_min': mean,   # rate_per_min: the format-1 name
               'first_seen': d[1], 'last_seen': d[2], 'saved_at': now}
        if unknown:
            rec['unknown_time'] = unknown
        out[key] = rec
    return out


def run_rates(dedup, base, minutes, vs='peak', start=None):
    """{key: (this run's rate, baseline rate)} for the patterns in the
    baseline. vs 'peak': the run's busiest bucket (the baseline's bucket
    size, buckets from start) against the baseline peak; 'mean', and
    format-1 patterns: the average over the run against the saved mean."""
    known, out = base.get('patterns', {}), {}
    bucket = base.get('bucket_minutes') or DEFAULT_BUCKET
    times = getattr(dedup, 'times', {})
    for key, d in dedup.patterns.items():
        b = known.get(key)
        if b is None:
            continue
        if vs == 'mean' or b.get('peak_is_mean'):
            out[key] = (d[0] / max(minutes, 1e-9), b['mean_rate'])
        else:
            counts, _ = bucket_counts(times.get(key, ()), start, bucket)
            out[key] = (peak_rate(d[0], counts, minutes, bucket), b['peak_rate_per_min'])
    return out


def compare(dedup, base, minutes, factor, min_lines, vs='peak', start=None):
    """{key: label} for this run's NEW and SPIKE patterns (others: no entry)."""
    labels, known = {}, base.get('patterns', {})
    rates = run_rates(dedup, base, minutes, vs, start)
    for key, d in dedup.patterns.items():
        if key not in known:
            labels[key] = '[NEW]'
            continue
        rate, brate = rates[key]
        if d[0] >= min_lines and (brate <= 0 or rate >= factor * brate):
            labels[key] = f'[SPIKE x{rate / brate:.1f}]' if brate > 0 else '[SPIKE]'
    return labels


def overlap_minutes(base, start, end):
    """Minutes by which the run window [start, end] overlaps the baseline's
    window (0.0 = not at all; None = the baseline has no window: format 1)."""
    bs, be = (base or {}).get('window_start'), (base or {}).get('window_end')
    if bs is None or be is None or start is None or end is None:
        return None
    return max(0.0, (min(end, be) - max(start, bs)) / 60.0)


def overlap_note(minutes):
    n = f"{minutes:.0f}" if minutes >= 1 else '<1'
    return f"this run overlaps the baseline window by {n} min; NEW/SPIKE are less meaningful"


def spike_note(base, vs):
    """One sentence for the AI digest header: what a SPIKE ratio compares."""
    if vs == 'mean':
        return "SPIKE ratios compare average lines per minute over the window with the baseline's average."
    bucket = base.get('bucket_minutes') or DEFAULT_BUCKET
    return (f"SPIKE ratios compare this run's busiest {bucket:g}-minute bucket with the "
            f"baseline's busiest one (lines per minute), so routine daily bursts stay normal.")


def _when(t):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(t))


def save_baseline(path, dedup, target, kind, minutes, replace=False, bucket_minutes=None,
                  start=None, end=None):
    """Write (merge unless replace) this run's patterns. start/end = the run's
    window (seconds since 1970; default: the last `minutes` before now).
    Returns a message; raises RuntimeError/OSError without writing if the old
    file is unusable or uses another bucket size."""
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    existed = os.path.exists(path)
    old, err = (None, None) if replace else load_baseline(path)
    if err:
        raise RuntimeError(f"existing baseline {path}: {err}; not overwritten. Fix or move "
                           f"it, or use --replace-baseline")
    obucket = (old or {}).get('bucket_minutes')
    if old and obucket and bucket_minutes and bucket_minutes != obucket:
        raise RuntimeError(f"existing baseline {path} uses {obucket:g}-min buckets, this run "
                           f"{bucket_minutes:g}: not merged. Use --baseline-bucket {obucket:g}, "
                           f"or --replace-baseline")
    bucket = bucket_minutes or obucket or DEFAULT_BUCKET
    end = time.time() if end is None else end
    start = end - minutes * 60 if start is None else start
    new = snapshot(dedup, minutes, now, bucket, start)
    overlap = overlap_minutes(old, start, end) if old else None
    merged, added, updated = dict(old['patterns']) if old else {}, 0, 0
    for key, n in new.items():
        o = merged.get(key)
        if o is None:
            merged[key], added = n, added + 1
            continue
        updated += 1
        seen = o.get('buckets_seen') or 0
        mean = max(o['mean_rate'], n['mean_rate'])
        rec = dict(o, count=(o.get('count') or 0) + n['count'],
                   buckets_seen=max(seen, n['buckets_seen']) if overlap else seen + n['buckets_seen'],
                   peak_count=max(o.get('peak_count') or 0, n['peak_count']),
                   peak_rate_per_min=max(o['peak_rate_per_min'], n['peak_rate_per_min']),
                   mean_rate=mean, rate_per_min=mean,
                   first_seen=o.get('first_seen') or n['first_seen'],
                   last_seen=n['last_seen'] or o.get('last_seen'), saved_at=now)
        rec.pop('peak_is_mean', None)   # this run measured a real peak for it
        unknown = (o.get('unknown_time') or 0) + (n.get('unknown_time') or 0)
        if unknown:
            rec['unknown_time'] = unknown
        merged[key] = rec
    ws, we = start, end
    if old and old.get('window_start') is not None:
        ws, we = min(ws, old['window_start']), max(we, old['window_end'])
    doc = {'format': FORMAT, 'note': NOTE, 'target': target, 'kind': kind, 'saved_at': now,
           'created_at': (old or {}).get('created_at') or now,
           'runs': int((old or {}).get('runs') or 0) + 1, 'window_minutes': round(minutes, 3),
           'bucket_minutes': bucket, 'window_start': round(ws), 'window_end': round(we),
           'window': f"{_when(ws)} -> {_when(we)} (local time)",
           'patterns': sorted(merged.values(), key=lambda p: -p['peak_rate_per_min'])}
    target_store.atomic_write(path, json.dumps(doc, indent=1, ensure_ascii=False) + '\n')
    how = 'replaced' if existed and replace else 'merged' if old else 'created'
    msg = (f"Baseline {how}: {path} ({len(merged)} patterns; {added} new, {updated} "
           f"updated; {bucket:g}-min buckets; mode 600)")
    if overlap:
        msg += f"\nNote: this run overlapped the saved window by {overlap:.0f} min; those lines are counted twice"
    return msg


def short_template(process, template):
    """The template without its '<TS> host proc[<PID>]: ' prefix."""
    m = re.match(r'<TS> \S+ ' + re.escape(normalize(process)) + r'\[<PID>\]: ?', template)
    return template[m.end():] if m else template


def changes_section(dedup, labels, base, factor, min_lines, limit=20, vs='peak', notes=()):
    """Report lines for 'Changes vs baseline' (notes: extra 'Note: ...' lines)."""
    out = [f"=== Changes vs baseline (saved {base.get('saved_at', '?')}, "
           f"{len(base.get('patterns', {}))} patterns) ==="]
    new = sum(1 for v in labels.values() if v.startswith('[NEW'))
    what = (f"the baseline peak rate, {base.get('bucket_minutes') or DEFAULT_BUCKET:g}-min buckets"
            if vs == 'peak' else "the baseline mean rate")
    out.append(f"{new} NEW (not in the baseline), {len(labels) - new} SPIKE (>= {factor:g}x "
               f"{what}, and >= {min_lines} lines)")
    out.extend(f"Note: {n}" for n in notes)
    if not labels:
        out.append("No new or spiking patterns vs baseline.")
        return out
    rows = sorted(((k, d) for k, d in dedup.patterns.items() if k in labels),
                  key=lambda kv: (0 if labels[kv[0]].startswith('[NEW') else 1,
                                  SEVERITY_RANK.get(kv[0][0], 9), -kv[1][0]))
    shown = []   # lines that would render identically are merged (display only)
    for (sev, proc, tpl), d in rows:
        text = short_template(proc, tpl)
        text = text if len(text) <= 110 else text[:107] + '...'
        shown.append(((labels[(sev, proc, tpl)], level_label(sev), proc, text), (d[0],)))
    merged = merge_same(shown)
    for (label, level, proc, text), (count,), n in merged[:limit]:
        out.append(f"  {label} [{level}] {proc} x{count}: {text}{patterns_suffix(n)}")
    if len(merged) > limit:
        out.append(f"  ... and {len(merged) - limit} more")
    return out


def info_text(path, top=10):
    """--baseline-info text and exit status (0 = found, 1 = none/unusable)."""
    base, err = load_baseline(path)
    if base is None:
        return f"No baseline at {path}" + (f": {err}" if err else
                                           " (create one with --save-baseline)"), 1
    pats = sorted(base['patterns'].values(), key=lambda p: -p['peak_rate_per_min'])
    out = [f"Baseline: {path}",
           f"  target {base.get('target', '?')} ({base.get('kind', '?')}), saved_at "
           f"{base.get('saved_at', '?')}, created {base.get('created_at', '?')}, "
           f"{base.get('runs', '?')} save(s), last window {base.get('window_minutes', '?')} min"]
    if base.get('bucket_minutes'):
        out.append(f"  window {base.get('window') or '?'}, {base['bucket_minutes']:g}-min buckets")
    if base.get('old_format'):
        out.append(f"  {OLD_FORMAT_HINT} ({base['old_format']} pattern(s) have no peak yet)")
    out += [f"  {len(pats)} patterns" + (f" ({base['bad_entries']} unreadable entries ignored)"
                                          if base.get('bad_entries') else ''),
            f"  top {min(top, len(pats))} by peak rate (lines/min: peak, mean):"]
    for p in pats[:top]:
        text = short_template(p['process'], p['template'])
        text = text if len(text) <= 80 else text[:77] + '...'
        out.append(f"  {p['peak_rate_per_min']:>8.3g} {p['mean_rate']:>8.3g}  "
                   f"[{level_label(p['severity'])}] {p['process']}: {text}")
    return '\n'.join(out), 0
