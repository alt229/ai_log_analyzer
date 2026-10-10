#!/usr/bin/env python3
#=============================================================================
# main.py - Entry point of ai_logs: collect system logs (local, SSH, Docker, Windows) and optionally get AI analysis
#=============================================================================
#
# WHAT IT DOES
# Command-line front end for the multi-file ai_logs tool. It gathers logs
# from this machine (--local), a remote Linux/Mac host over SSH (--host),
# Docker containers on that host (--docker), or a remote Windows machine's
# Event Log over WMI (--windows). Lines are grouped and filtered by severity
# by LogAnalyzer, printed (or written to a file / JSON), and can then be sent
# to Claude, Gemini or ChatGPT for a summary. An optional "deep dive" asks
# the AI to investigate chosen numbered issues from that summary. main.py
# itself only parses arguments, wires the sibling modules together, and
# formats the AI's markdown-ish reply for the terminal.
#
# USAGE
# python3 main.py                 (no args: prints help, exit 0)
# Scan target (at least one needed, else a warning + help + exit 1):
#   --local                  local Mac/Linux logs
#   --host H [--user U] [--port 22] [--key FILE]   SSH to a remote host
#                            (--user defaults to your local username)
#   --docker                 add Docker container logs (REQUIRES --host)
#   --windows --win-host H   Windows Event Log via WMI
# Time:  -t/--time DURATION: 90s, 15m, 2h, 1d, 1h30m (any case); a bare
#   number is hours (-t 6 = 6h). Default 15m. Local/SSH/Docker only.
# Output: --no-color  --json  --full  -o/--output FILE  --debug  --summary
#   --quiet   only: noise filter line, "Changes vs baseline" (no baseline:
#             totals + top 10 patterns), the AI result (CAVEATS)
#   --status-file PATH   after the run, write a small JSON result for
#             automation (INPUTS / OUTPUTS); the launchd wrapper reads it
# Severity: --only-errors | --only-warnings | --only-info ; or
#   --ignore {info,warnings,errors} [...]
#   --all-levels   macOS --local: every log level, old keyword filter
#                  (default there: only error and fault messages)
# AI: --ai {claude,gemini,chatgpt}  --api-key KEY  --system-info FILE.json
#   --compare (all providers that have a key)
#   --max-examples N (1)      raw example lines per log pattern for the AI
#   --ai-max-chars N (12000)  size cap for the log patterns sent to the AI
#   --max-input-tokens N      don't send a bigger request, exit 1 (off)
#   --dry-run-ai              build the request, print its size, don't send
#   Claude only: --model sonnet|opus|haiku|claude-... (default sonnet =
#   claude-sonnet-5-5, or claude_model in config.yaml)  --no-fallback
#   --deep-dive [N ...]   no numbers = ask interactively after analysis;
#                         numbers = investigate those issues without asking
# Docker: --container NAME  --no-container-stats  --docker-socket PATH
# Windows: --win-user (Administrator)  --win-password  --win-domain
#   --win-hashes LM:NT  --win-time {hour,day,week,month,all} (month)
#   --win-logs LOG [...] (System Application Security)
#   --win-level {critical,error,warning,information,all} (warning)
#   --win-show-noisy  --win-max-events N (5000 per channel)
# Config (act then exit 0, no scanning):
#   --set-api-key PROVIDER [KEY]   (no KEY, or "-", = hidden prompt)
#   --show-config   --reset-config [--yes]   (asks y/N unless --yes)
# Per analyzed machine (folder ~/.local/share/ai_logs/<target>/, CAVEATS):
#   --noise-file PATH    noise filters (default <folder>/noise.yaml, read
#                        automatically if it exists)  --no-noise-filter
#   --show-noise         list each filter with the lines it skipped
#   --suggest-noise [N]  print the top N (10) patterns as noise.yaml entries
#     [--write-noise 1,3 | ID,ID]  append exactly those suggestions to it
#   --save-baseline [--replace-baseline]   --no-baseline   --baseline-info
#   --spike-factor X (5)  --spike-min N (5)  --spike-vs peak|mean (peak)
#   --baseline-bucket MIN  with --save-baseline: bucket for peak rates (60)
#   --report-noise       per-filter counts, top normal and NEW/SPIKE
#                        patterns with ids for --write-noise (read-only)
#   --ai-changes-only    send only NEW/SPIKE patterns (none = no AI call)
#   --list-targets       print hosts.json: each machine's folder, the
#                        names/IPs used for it, short ids, last seen
#   --rename-target OLD NEW   rename folder OLD (or the folder of name/IP
#                        OLD) to NEW; OLD stays a name for it. Both: no
#                        connection, no scan; exit 0 (1 = refused)
#
# REQUIRES
# Python 3 (run with the alt229-dev venv: colorama is only there). Sibling
# modules in the same folder (found via sys.path): collector, analyzer,
# ai_providers, local_insights, config, plus docker_collector,
# windows_collector, windows_analyzer loaded on demand. config.py needs
# PyYAML (inferred from its import). --windows needs impacket (inferred
# from the error message); --ai needs anthropic, google-genai, openai
# (install message at the end of the file). Network: SSH to --host, WMI/SMB
# to --win-host, HTTPS to the AI provider. Docker needs access to the
# remote Docker socket. Credentials: SSH key/agent, Windows password or NTLM
# hash, AI API keys. Config file: ~/.config/ai_logs/config.yaml.
#
# SIDE EFFECTS
# - Creates ~/.config/ai_logs/ and config.yaml on first run of ANY command
#   (Config() is built before anything else).
# - --set-api-key writes the key in plain text into config.yaml.
# - --reset-config asks y/N (unless --yes), renames config.yaml to
#   config.yaml.bak-YYYYmmdd-HHMMSS (mode 600; it holds your API keys; an
#   existing backup of that name is never overwritten), then writes fresh
#   defaults. All stored API keys are gone from config.yaml.
# - -o/--output: the log report is written there (file overwritten), and AI
#   output and deep-dive text are APPENDED to the same file.
# - With --ai/--compare: sends a de-duplicated digest of the collected log
#   lines (one entry per pattern: count, first/last time, example lines;
#   capped by --ai-max-chars), plus --system-info / Docker stats, to the
#   chosen third-party AI provider. A one-line size summary goes to stderr
#   first. For Claude a free count_tokens request comes before each
#   analysis (exact input size).
# - --save-baseline writes ~/.local/share/ai_logs/<target>/baseline.json
#   (baseline-docker.json with --docker); --write-noise appends to
#   noise.yaml there. Folder 700, files 600, temp file + rename; a failed
#   write leaves the .tmp file. Nothing is deleted. Baselines hold masked
#   log templates that can still contain host names and paths: private.
# - --local on macOS reads LocalHostName from the network prefs plist.
# - --host / --local: hosts.json in ~/.local/share/ai_logs/ (mode 600)
#   records which folder is which machine: machine-id (Linux) or
#   IOPlatformUUID (macOS), SSH host key fingerprints, each name/IP used,
#   dates. --host runs ONE extra command over SSH for it (machine-id file
#   or ioreg, hostname); --local reads the same here (ioreg on macOS).
#   --rename-target renames a folder there. Nothing is deleted.
# - Opens SSH / WMI connections to remote hosts; reads logs only (inferred).
#
# CAVEATS & GOTCHAS
# - --reset-config wipes stored API keys. It asks first (or --yes) and keeps
#   a backup copy; old backups pile up in ~/.config/ai_logs/, delete them.
# - --docker only works together with --host; without it the script stops
#   with a usage error (exit 2) before collecting. Docker lines go into the
#   same analyzer as the SSH logs; the one report is printed after both.
# - -t/--time does not affect Windows; use --win-time. The Windows scan
#   defaults to a whole month at level warning.
# - --win-password on the command line is visible in ps/shell history. If
#   neither password nor hashes is given you are prompted (getpass, safe).
#   The password prompt, its hand-off to the Windows collector and the API
#   key lookups are variables, not literals (the secret scanner flags them).
# - --deep-dive needs a single --ai provider; with --compare or without --ai
#   it is a usage error (exit 2), as is a non-numeric issue number.
#   --deep-dive N ... investigates exactly those issues and stops.
#   --deep-dive alone prompts (input()): numbers, "all" (= 1-5), or Enter/q
#   to finish; it loops until you quit. Piped/EOF stdin ends it.
# - AI key lookup order: --api-key, then the env var (ANTHROPIC_API_KEY,
#   GOOGLE_API_KEY, OPENAI_API_KEY), then config.yaml. With --ai this is
#   checked before collecting; no key = exit 1. --compare uses env var or
#   config.yaml per provider and skips providers that have neither.
# - --json and --summary currently have no effect: the analyzer ignores
#   them (inferred from code reading). Their --help says "(not implemented
#   yet)". --max-examples only affects local/SSH/Docker patterns, not the
#   Windows summary.
# - AI input: matched lines are grouped into patterns (timestamps, PIDs,
#   numbers, IDs, IPs, MACs, paths masked), errors first, then by count.
#   The lowest-priority patterns are dropped to fit --ai-max-chars (the
#   only size limit; 12000 chars is roughly 7k tokens of macOS log text).
#   The terminal report is unchanged.
# - Remote windows (SSH journalctl, docker logs) are relative ("900s ago"),
#   so the remote host's clock and time zone decide them. Local macOS and
#   Linux use an absolute local start time, as before.
# - macOS --local runs `log show --style ndjson` with the predicate
#   (logType == "error" OR logType == "fault"): only real errors and faults,
#   whatever their wording (field name from `log help predicates` on macOS
#   26; an older macOS that doesn't know it makes log show fail = exit 1).
#   Faults are shown as [FAULT] and errors as [ERROR] (the macOS log
#   levels, not severity judgements; the AI is told so) in "Changes vs
#   baseline", the --quiet top 10, --report-noise, --suggest-noise notes,
#   --baseline-info and the AI digest. Faults still sort first. The full
#   terminal report lists both under [ERROR]. Lines in "Changes vs
#   baseline" and in --report-noise that would read the same (same label,
#   level, process, shortened text and id) are shown once with summed
#   counts and "(N patterns)"; the baseline keeps them apart. Other
#   sources keep their labels. --all-levels uses the old keyword
#   predicate instead (message contains error/warning/failure/failed, or
#   process "system"). --only-warnings, --only-info and --ignore errors
#   imply --all-levels. Local Linux, SSH and Docker fetch as before.
# - macOS process names come from the ndjson record, so names with spaces
#   stay whole ("Bartender 6"). The `log` process's note about a `log show`
#   run ("log run noninteractively ... 'log' 'show'") is dropped.
# - "Total matches found: N lines" counts matched lines after the ignore
#   patterns, the same N as "N matched" in the AI size line. The distinct
#   message count (the old number) is shown next to it.
# - <target> is the folder of the machine ANALYZED. --host connects (and
#   --local looks itself up) BEFORE the baseline and noise.yaml are read:
#   a machine already in hosts.json (same machine-id, else same SSH host
#   key) keeps its folder under any new name or IP; one stderr line says
#   so. A new machine's folder is named as before: --local = this Mac's
#   LocalHostName (else the host name), lower-case, no domain; --host H =
#   H as typed, lower-case, ".local" removed. Folders from before
#   hosts.json are adopted by name, never moved. A known name/IP that now
#   answers as a DIFFERENT machine (IP reused, reinstall) gets a NEW
#   folder (NAME or NAME-2) and a WARNING line. Not identified (connection
#   failed, no id): folder by name, as before. --baseline-info does not
#   connect (name lookup only). --docker shares the host's folder.
# - Noise filters drop lines before the report, the AI digest and the
#   baseline: a broad entry hides real problems. One line per run names
#   the file used. Bad entries are skipped with a warning. On macOS
#   --local the first 100 also go into the log show predicate as
#   AND NOT (...); those lines are not counted.
# - NEW / SPIKE compare (severity, process, template) with the baseline.
#   SPIKE (default --spike-vs peak): this run's busiest bucket (the saved
#   baseline's bucket size, 60 min by default) against the baseline's
#   busiest, in lines per minute. A run shorter than one bucket uses its
#   average rate, so a routine burst inside a very short -t can still
#   spike. --spike-vs mean = the old average-over-the-window comparison
#   (daily bursts then spike, e.g. x12.0 for -t 2h vs a 24h baseline).
#   Merging keeps the highest peak and sums the counts. A baseline saved
#   before peak-quiet.patch gets one hint line on stderr and is compared
#   as before until you save it again with --replace-baseline.
# - A run whose window overlaps the baseline's window gets a note (stderr,
#   report, AI prompt): NEW/SPIKE are less meaningful then.
# - macOS --local drops log lines whose pid is this tool's own or its
#   `log show` child's (exact processID match).
# - --quiet: the noise filter line, "Changes vs baseline" (no baseline: the
#   totals and the top 10 patterns), the AI result or the skip line; the -o
#   file gets the same. stderr (errors, the AI size line), exit codes and
#   what the AI gets are unchanged. Windows output is not shortened.
#   --ai-changes-only needs a saved baseline (else exit 1); with no
#   changes it skips the AI call (exit 0, or 1 if a collection failed).
# - The AI severity badge is the AI's own "SEVERITY: low|medium|high|
#   critical" first line (removed from the shown text) or a stated overall
#   severity; failing both, a keyword guess labelled "(heuristic)".
# - Claude: a refusal (stop_reason "refusal", e.g. on security logs) is an
#   error (exit 1). Server-side refusal fallback is on unless --no-fallback;
#   if the installed anthropic SDK lacks it, one note is printed and the
#   plain call is used. Interactive --deep-dive rounds use prompt caching.
# - --max-input-tokens uses Claude's exact count; for Gemini/ChatGPT, or if
#   counting fails, the chars/4 estimate. --dry-run-ai still needs a key.
# - If no log data was collected the AI step is skipped, not failed.
# - When only --windows is used, the Windows text summary is what is sent
#   to the AI; with --local/--host too, it is attached to the analyzer.
# - --ignore warnings works by stripping a trailing "s" from the word.
# - Most errors are printed and the script carries on (a Windows failure
#   does not stop later steps), but if any log collection, AI, Windows or
#   Docker step failed the exit status is 1. Exit 1 on Ctrl-C. A failed
#   collection (log show / journalctl / SSH / docker error or non-zero exit)
#   prints the command's own error on stderr. "No logs were collected" means
#   the command worked and found nothing: a warning, exit 0.
# - SSH uses paramiko AutoAddPolicy: any host key is accepted unchecked
#   (collector.py, inferred).
# - analyzer.py's "success" ignore pattern also matches "unsuccessful", so
#   such error lines can be silently dropped (regex check by reviewer).
# - Config 'default_settings' (color, summary, max_examples) exist in
#   config.yaml but main.py never reads them (inferred from this file).
# - config.py: if config.yaml can't be read or parsed, one error is printed
#   and built-in defaults are used for that run. The file is left untouched
#   and --set-api-key refuses to overwrite it: fix it by hand, or use
#   --reset-config (which backs it up first).
# - config.yaml holds API keys in plain text and is created with default
#   permissions (observed -rw-r--r--). Suggest: chmod 600 it.
# - The epilog examples say "python main.py"; use python3 / the venv.
# - Help text says Windows via "WMI"; also uses SMB for OS detection.
#
# EXAMPLES
# python3 main.py --local -t 30m --only-errors
#   Last 30 minutes of local logs, errors only.
# python3 main.py --local --ai claude --dry-run-ai
#   Last 15 minutes: build the AI request, print its exact size, send nothing.
# python3 main.py --local -t 15m --ai claude --ai-changes-only
#   Only patterns that are NEW or SPIKE vs this Mac's saved baseline go to Claude.
# python3 main.py --local -t 2h --ai claude --ai-changes-only --quiet
#   The same, short: changes vs baseline and the AI result only.
# python3 main.py --host server1 --user admin --key ~/.ssh/id_ed25519 -t 6 --docker --ai claude
#   Six hours over SSH incl. Docker logs, then AI summary.
# python3 main.py --windows --win-host 192.168.1.50 --win-user Administrator --win-time day --win-level error --ai claude --deep-dive 1 3
#   Windows errors from the last day, AI summary, auto deep-dive on 1 and 3.
#
# INPUTS / OUTPUTS
# Input: live logs; optional --system-info JSON file; config.yaml.
# Output: coloured terminal report (--no-color: plain), optional -o file
# (always plain text, no colour codes). Exit 0 on success/help/config
# commands; 2 on bad arguments (checked before collecting); 1 on fatal
# errors, a missing AI key, a cancelled --reset-config, a refused
# --set-api-key, or if any log collection, AI, Windows or Docker step failed.
# --status-file PATH: JSON {"time", "target", "severity" (low|medium|high|
# critical|null), "severity_source" (ai|heuristic|null), "ai_called",
# "ai_skipped_reason", "new", "spike", "lines" (processed, after noise
# filters), "patterns", "exit_code"}, written after the run (also when it
# fails, unless the arguments could not be parsed at all), via PATH.tmp +
# rename, mode 600, parent folder created 700. It may hold host names.
#
# STATUS
# Triage result was static-only. Syntax is OK under the venv. Not run: the sandbox
# refused because sibling files match dangerous patterns (config.py,
# file removal in reset_config; Windows event-ID strings in windows_analyzer).
# The check tool's "missing module" list is a false positive: those are
# sibling files. Behaviour above is from reading main.py and config.py;
# other siblings were not read, so their details are (inferred).
#
# ORIGIN / HISTORY
# No author, version or date in the file (line 2 is just "# main.py").
# History:
# 2026-10-09 - Script Wrangler: one folder per machine (hosts.json: the
#   machine-id / SSH host key is checked right after connecting, before
#   the baseline and noise.yaml are read); --list-targets, --rename-target
#   (hostid.patch).
#-----------------------------------------------------------------------------
# Header written 2026-10-08 by Script Wrangler (Claude). Last test then:
# PASS-STATIC. Items marked (inferred) come from reading the code, not from
# running it.
#=============================================================================
# main.py
import argparse
import sys
import os
import re
import json
import getpass
import time
from typing import Dict
import colorama
from colorama import Fore, Style

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from collector import LogCollector
from analyzer import LogAnalyzer
from ai_providers import get_ai_provider, _build_prompt, CLAUDE_MODELS, DEFAULT_CLAUDE_MODEL
from config import Config
import noise_filters as nf
import baseline as bl
import target_store
from log_dedup import level_label, merge_same, patterns_suffix

# Env vars the providers in ai_providers.py already fall back to
AI_KEY_ENV = {'claude': 'ANTHROPIC_API_KEY', 'gemini': 'GOOGLE_API_KEY', 'chatgpt': 'OPENAI_API_KEY'}

# Colour codes, stripped from anything written to the -o file
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# --status-file: what this run did, filled in by _main(), written by main()
RUN_STATUS = {}
AI_SEVERITIES = ('low', 'medium', 'high', 'critical')


def status_counts(analyzer):
    """--status-file: NEW/SPIKE counts, lines processed and patterns of this run."""
    labels = getattr(analyzer, 'baseline_labels', None) or {}
    new = sum(1 for v in labels.values() if v.startswith('[NEW'))
    RUN_STATUS.update(new=new, spike=len(labels) - new, lines=analyzer.total_lines_processed,
                      patterns=len(analyzer.dedup.patterns))


def status_ai(recommendations):
    """--status-file: the AI's severity badge and where it came from."""
    sev = str((recommendations or {}).get('severity') or '').lower()
    if sev in AI_SEVERITIES:
        src = 'heuristic' if recommendations.get('severity_source') == 'heuristic' else 'ai'
        old = RUN_STATUS.get('severity')   # --compare: keep the most severe answer
        if old is None or AI_SEVERITIES.index(sev) > AI_SEVERITIES.index(old):
            RUN_STATUS.update(severity=sev, severity_source=src)


def write_status_file(path, exit_code):
    """--status-file: write this run's result as JSON via PATH.tmp + rename (a reader
    never sees half a file), mode 600, parent folder created 700 if missing.
    A problem is reported on stderr only; it does not change the exit code."""
    s = RUN_STATUS
    called = bool(s.get('ai_called'))
    reason = None if called else s.get('ai_skipped_reason')
    if not called and reason is None:
        reason = ('not called: the run stopped before the AI step (see stderr)'
                  if s.get('ai_requested') else 'not requested')
    data = {'time': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'target': s.get('target'),
            'severity': s.get('severity'), 'severity_source': s.get('severity_source'),
            'ai_called': called, 'ai_skipped_reason': reason,
            'new': s.get('new', 0), 'spike': s.get('spike', 0), 'lines': s.get('lines', 0),
            'patterns': s.get('patterns', 0), 'exit_code': exit_code}
    path = os.path.abspath(os.path.expanduser(path))
    tmp = path + '.tmp'
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            os.fchmod(fh.fileno(), 0o600)
            json.dump(data, fh, indent=1)
            fh.write('\n')
        os.replace(tmp, path)
    except OSError as e:
        print(f"{Fore.RED}--status-file: {path} not written: {e}{Style.RESET_ALL}", file=sys.stderr)


def resolve_api_key(provider, config, cli_key=None):
    """Key for provider: --api-key, else its env var, else config.yaml (or None)."""
    return cli_key or os.getenv(AI_KEY_ENV[provider]) or config.get_api_key(provider)


MAX_TIME_DAYS = 3650   # -t upper limit (10 years); keeps the date maths in range
_DURATION_PART = re.compile(r'(\d+(?:\.\d+)?|\.\d+)([smhd])')
_UNIT_SECONDS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}


def parse_duration(text):
    """argparse type for -t/--time: 90s, 15m, 2h, 1d, 1h30m (any case).
    A bare number means hours (6 = 6h, 0.5 = 30m). Returns hours (float)."""
    s = text.strip().lower().replace(' ', '')
    if re.fullmatch(r'\d+(?:\.\d+)?|\.\d+', s):
        seconds = float(s) * 3600
    else:
        parts = _DURATION_PART.findall(s)
        if not parts or ''.join(n + u for n, u in parts) != s:
            raise argparse.ArgumentTypeError(
                f"invalid duration {text!r}: use e.g. 90s, 15m, 2h, 1d or 1h30m "
                f"(s/m/h/d), or a bare number of hours such as 6")
        seconds = sum(float(n) * _UNIT_SECONDS[u] for n, u in parts)
    if seconds < 1:
        raise argparse.ArgumentTypeError(f"duration {text!r} must be at least 1 second")
    if seconds > MAX_TIME_DAYS * 86400:
        raise argparse.ArgumentTypeError(f"duration {text!r} is too long (at most {MAX_TIME_DAYS}d)")
    return seconds / 3600


def format_duration(hours):
    """Hours (float) for messages: 0.25 -> 15m, 1.5 -> 1h30m, 0.025 -> 1m30s."""
    secs, out = int(round(hours * 3600)), ''
    for unit, size in (('d', 86400), ('h', 3600), ('m', 60), ('s', 1)):
        if secs >= size:
            n, secs = divmod(secs, size)
            out += f'{n}{unit}'
    return out or '0s'


def positive_int(text):
    """argparse type: a whole number >= 1."""
    try:
        n = int(text)
    except ValueError:
        n = 0
    if n < 1:
        raise argparse.ArgumentTypeError(f"expected a whole number >= 1, got {text!r}")
    return n


def positive_float(text):
    """argparse type: a number > 0 (e.g. --spike-factor 2.5)."""
    try:
        x = float(text)
    except ValueError:
        x = 0.0
    if not 0 < x < float('inf'):
        raise argparse.ArgumentTypeError(f"expected a number > 0, got {text!r}")
    return x


def suggestion_choices(text):
    """argparse type for --write-noise: suggestion numbers (1,3,5) and/or the
    6-character ids that --suggest-noise prints (stable between runs)."""
    out = []
    for p in text.replace(' ', ',').split(','):
        p = p.strip().lower()
        if not p:
            continue
        if len(p) == 6 and all(c in '0123456789abcdef' for c in p):
            out.append(p)
        elif p.isdigit() and int(p) >= 1:
            out.append(int(p))
        else:
            raise argparse.ArgumentTypeError(
                f"expected suggestion numbers or ids like 1,3 or 3fa2c1, got {text!r}")
    if not out:
        raise argparse.ArgumentTypeError("no suggestion numbers given")
    return out


def write_noise(choices, entries, path, by_id=None):
    """--write-noise: append the chosen suggestions to noise.yaml. True = something failed.
    Numbers pick from this run's --suggest-noise list; ids from every suggestion of
    this run (by_id from nf.suggest), so ids shown by --report-noise work too."""
    by_id = by_id or {nf.entry_id(e): [e] for e in entries if e}
    chosen, missing, twice = [], [], []
    for c in choices:
        if isinstance(c, str):
            found = by_id.get(c) or []
            if len(found) > 1:
                twice.append(c)
                continue
            e = found[0] if found else None
        else:
            e = entries[c - 1] if c <= len(entries) else None
        (chosen if e else missing).append(e if e else c)
    if missing:
        print(f"{Fore.YELLOW}--write-noise: not written: {', '.join(map(str, missing))} (not in "
              f"this run, or commented out as too broad){Style.RESET_ALL}", file=sys.stderr)
    if twice:
        print(f"{Fore.YELLOW}--write-noise: not written: {', '.join(twice)} (that id fits more than "
              f"one suggestion this run; use its number instead){Style.RESET_ALL}", file=sys.stderr)
        missing += twice
    if not chosen:
        return True
    try:
        added, dups = nf.append_entries(path, chosen)
    except (OSError, RuntimeError) as e:
        print(f"{Fore.RED}--write-noise: {e}{Style.RESET_ALL}", file=sys.stderr)
        return True
    print(f"--write-noise: {added} entr{'y' if added == 1 else 'ies'} appended to {path}"
          + (f" ({len(dups)} already there)" if dups else '')
          + ". Check the file; it is used from the next run on.")
    return bool(missing)


def quiet_report(analyzer, noise_line, noise, changes, top=10):
    """--quiet: the noise filter line, then "Changes vs baseline" or, without a
    baseline, the totals and the top patterns by count (one line each)."""
    out = []
    if noise_line:
        out.append(noise_line + (f": {noise.summary()}" if noise.filters else ''))
    if changes is not None:
        return '\n'.join(out + list(changes))
    pats = sorted(analyzer.dedup.patterns.items(), key=lambda kv: -kv[1][0])
    out.append(f"Total lines processed: {analyzer.total_lines_processed}; matched "
               f"{analyzer.total_matches} lines -> {len(pats)} patterns (no baseline; top "
               f"{min(top, len(pats))} by count):")
    for (sev, proc, tpl), d in pats[:top]:
        text = bl.short_template(proc, tpl)
        out.append(f"  x{d[0]} [{level_label(sev)}] {proc}: {text if len(text) <= 100 else text[:97] + '...'}")
    return '\n'.join(out)


def noise_report(analyzer, noise, noise_line, base, labels, rates, spike_vs, own_dropped=0, top=10):
    """--report-noise text (read-only): what the noise filters and the baseline did."""
    out = ['=== Noise report ===']
    if noise.filters:
        out.append(f"Noise filters: {noise.summary()}")
        out.extend(noise.brief())
    else:
        out.append(noise_line or 'Noise filters: none')
    if own_dropped:
        out.append(f"This tool's own log lines dropped (pid match): {own_dropped:,}")
    if base is None:
        out.append('No baseline in use: no NEW/SPIKE (save one with --save-baseline).')
        return '\n'.join(out)
    ids = {k: (g['id'] if g['writable'] else '- (too broad)')
           for g in nf.suggestion_groups(analyzer.dedup) for k in g['keys']}

    def rows(kvs):
        """Display rows; ones that would read the same (label, level, process,
        shortened text, id) are merged: counts and rates summed, '(N patterns)'."""
        shown = []
        for k, d in kvs:
            text = bl.short_template(k[1], k[2])
            text = text if len(text) <= 70 else text[:67] + '...'
            rate, brate = rates.get(k, (0, 0))
            shown.append(((labels.get(k), level_label(k[0]), k[1], text, ids.get(k, '?')),
                          (d[0], rate, brate)))
        return merge_same(shown)

    def row(key, nums, n):
        label, level, proc, text, ident = key
        count, rate, brate = nums
        first = label or (f"x{rate / brate:.1f}" if brate > 0 else 'x-')
        return f"  {first} [{level}] {proc} x{count}: {text}  id {ident}{patterns_suffix(n)}"

    pats = sorted(analyzer.dedup.patterns.items(), key=lambda kv: -kv[1][0])
    normal = rows(kv for kv in pats if kv[0] not in labels)
    changed = rows(kv for kv in pats if kv[0] in labels)
    n_normal = sum(n for _, _, n in normal)
    n_changed = sum(n for _, _, n in changed)
    out.append(f"Normal (in the baseline): {n_normal} patterns; top {min(top, len(normal))} by "
               f"count, this run's rate vs the baseline {spike_vs}:")
    out.extend(row(*r) for r in normal[:top])
    out.append(f"NEW/SPIKE: {n_changed} patterns; top {min(top, len(changed))} by count "
               f"(to filter one: --suggest-noise --write-noise ID):")
    out.extend(row(*r) for r in changed[:top])
    return '\n'.join(out)


def claude_model(text):
    """argparse type for --model: sonnet / opus / haiku, or a full claude-... ID."""
    s = text.strip()
    if s.lower() in CLAUDE_MODELS:
        return CLAUDE_MODELS[s.lower()]
    if s.startswith('claude-'):
        return s
    raise argparse.ArgumentTypeError(
        f"unknown Claude model {text!r}: use {', '.join(CLAUDE_MODELS)}, "
        f"or a full model ID starting with claude-")


def prepare_ai_logs(analyzer, log_results, system_info, args, provider_name, ai_provider):
    """What to send to the AI, plus a one-line size summary on stderr.
    Local/SSH/Docker results get the de-duplicated pattern digest (log_dedup.py)
    instead of the old per-group examples, capped at --ai-max-chars.
    Returns (payload, tokens): Claude's exact
    count, or the chars/4 estimate when no exact count is available."""
    model = getattr(ai_provider, 'model', None)
    who = f"{provider_name} ({model})" if model else provider_name
    if isinstance(log_results, dict):
        old_chars = len(_build_prompt(log_results, system_info))
        # Everything except the digest: framing, Windows summary, system info
        rest = len(_build_prompt(dict(log_results, _ai_digest='-'), system_info)) - 1
        total = log_results.get('stats', {}).get('total_lines', 0)
        digest, info = analyzer.dedup.render(
            max_chars=args.ai_max_chars - rest,
            examples=args.max_examples, total_lines=total,
            window=format_duration(args.time) if (args.local or args.host) else None,
            labels=getattr(analyzer, 'baseline_labels', None),
            only_labeled=getattr(args, 'ai_changes_only', False),
            note=getattr(analyzer, 'baseline_note', None))
        payload = dict(log_results, _ai_digest=digest)
        chars = len(_build_prompt(payload, system_info))
        what = (f"{total:,} lines collected, {info['lines']:,} matched -> "
                f"{info['patterns']:,} patterns ({info['shown']:,} sent, "
                f"{info['omitted']:,} omitted)")
        if info.get('left_out'):
            what += f", {info['left_out']:,} normal left out (--ai-changes-only)"
        if getattr(analyzer, 'noise_summary', None):
            what += f"; {analyzer.noise_summary}"
        what += f"; {chars:,} chars (old format: {old_chars:,})"
    else:
        payload, chars = log_results, len(_build_prompt(log_results, system_info))
        what = f"Windows summary; {chars:,} chars"
    exact = ai_provider.count_tokens(payload, system_info) if hasattr(ai_provider, 'count_tokens') else None
    tokens = exact if exact is not None else chars // 4
    label = 'exact' if exact is not None else 'estimate, chars/4'
    print(f"AI request for {who}: {what}; {tokens:,} input tokens ({label})", file=sys.stderr)
    if exact is None and args.debug and getattr(ai_provider, 'count_error', None):
        print(f"DEBUG: count_tokens failed: {ai_provider.count_error}", file=sys.stderr)
    return payload, tokens


def over_token_limit(args, tokens):
    """True (with an explanation) if --max-input-tokens is set and exceeded."""
    if args.max_input_tokens and tokens > args.max_input_tokens:
        print(f"{Fore.RED}Not sent: {tokens:,} input tokens is over --max-input-tokens "
              f"{args.max_input_tokens:,}. Narrow it: a smaller -t (now {format_duration(args.time)}), "
              f"--only-errors, or a lower --ai-max-chars (now {args.ai_max_chars:,}).{Style.RESET_ALL}")
        return True
    return False


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Advanced log analyzer for system logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Analyze local Mac/Linux logs for the last 15 minutes (the default)
    python main.py --local

    # Last 2 hours (-t takes 90s, 15m, 2h, 1d, 1h30m; a bare number = hours)
    python main.py --local -t 2h

    # Show how big the AI request would be (exact tokens for Claude), send nothing
    python main.py --local --ai claude --dry-run-ai

    # Local logs, errors only
    python main.py --local -t 1 --only-errors

    # Remote Linux via SSH
    python main.py --host server1.example.com --user admin --key ~/.ssh/id_ed25519 -t 6

    # Remote Windows via WMI (prompts for password)
    python main.py --windows --win-host 192.168.1.50 --win-user Administrator

    # Remote Windows, last day, errors only, with AI summary
    python main.py --windows --win-host 192.168.1.50 --win-user Administrator --win-time day --win-level error --ai claude

    # AI analysis
    python main.py --local -t 1 --ai claude
    python main.py --local -t 1 --ai gemini
    python main.py --local -t 1 --ai chatgpt

    # Deep dive — prompts interactively after analysis
    python main.py --windows --win-host 192.168.1.50 --win-user Administrator --ai claude --deep-dive

    # Deep dive — auto investigate issues 1 and 3 without prompting
    python main.py --windows --win-host 192.168.1.50 --win-user Administrator --ai claude --deep-dive 1 3
        """)


    # Time window options
    parser.add_argument('-t', '--time', type=parse_duration, default='15m', metavar='DURATION',
                      help='How far back to look: 90s, 15m, 2h, 1d or 1h30m (any case); a bare '
                           'number means hours, e.g. -t 6 = 6h (default: 15m). Local/SSH/Docker '
                           'only: -t does not apply to Windows, use --win-time')

    # Scan target — at least one required
    target_group = parser.add_argument_group('scan target (choose one or more)')
    target_group.add_argument('--local', action='store_true',
                          help='Analyze logs on the local Mac/Linux machine')

    # Remote connection options
    remote_group = parser.add_argument_group('remote connection options (SSH — Linux/Mac)')
    remote_group.add_argument('--host', help='Remote host to analyze logs from')
    remote_group.add_argument('--user', help='SSH username for remote host (default: your local username)')
    remote_group.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    remote_group.add_argument('--key', help='Path to SSH private key file')

    # Output options
    output_group = parser.add_argument_group('output options')
    output_group.add_argument('--no-color', action='store_true', help='Disable colored output')
    output_group.add_argument('--json', action='store_true', help='Output results as JSON (not implemented yet)')
    output_group.add_argument('--full', action='store_true', help='Show full messages without truncation')
    output_group.add_argument('-o', '--output', help='Write output to file')
    output_group.add_argument('--debug', action='store_true', help='Show debug information')
    output_group.add_argument('--summary', action='store_true', help='Show summarized output (not implemented yet)')
    output_group.add_argument('--quiet', action='store_true',
                              help='Short output: noise filter line, changes vs baseline (no baseline: '
                                   'totals and top 10 patterns), AI result. stderr unchanged')
    output_group.add_argument('--status-file', metavar='PATH',
                              help='After the run (also on failure), write a small JSON result to PATH '
                                   '(severity, NEW/SPIKE counts, AI called or why not, exit code); '
                                   'mode 600, parent folder created (700)')

    # Severity filter options
    filter_group = parser.add_argument_group('severity filter options')
    only_group = filter_group.add_mutually_exclusive_group()
    only_group.add_argument('--only-errors', action='store_true',
                          help='Show only error messages')
    only_group.add_argument('--only-warnings', action='store_true',
                          help='Show only warning messages')
    only_group.add_argument('--only-info', action='store_true',
                          help='Show only info messages')
    filter_group.add_argument('--ignore', nargs='+', choices=['info', 'warnings', 'errors'],
                          help='Ignore specific message types')
    filter_group.add_argument('--all-levels', action='store_true',
                          help='macOS --local only: fetch every log level with the old keyword filter '
                               '(error/warning/failure/failed in the message, or process "system"). '
                               'Default: only error and fault messages. Implied by --only-warnings, '
                               '--only-info and --ignore errors')

    # AI analysis options
    ai_group = parser.add_argument_group('AI analysis options')
    ai_group.add_argument('--ai', metavar='PROVIDER', type=str.lower, choices=list(AI_KEY_ENV),
                       help='Enable AI analysis using specified provider (claude, gemini, or chatgpt)')
    ai_group.add_argument('--max-examples', type=positive_int, default=1, metavar='N',
                       help='Raw example lines per log pattern sent to the AI (default: 1; '
                            'local/SSH/Docker logs, not the Windows summary)')
    ai_group.add_argument('--ai-max-chars', type=positive_int, default=12000, metavar='N',
                       help='Size cap for the log patterns sent to the AI, in characters (default: '
                            '12000, roughly 7k tokens of macOS log text). Lowest-priority '
                            'patterns are dropped first')
    ai_group.add_argument('--model', type=claude_model, metavar='MODEL',
                       help='Claude model: sonnet (default, claude-sonnet-5-5), opus, haiku, or a '
                            'full claude-... ID. If omitted: claude_model in config.yaml, else sonnet')
    ai_group.add_argument('--max-input-tokens', type=positive_int, metavar='N',
                       help="Don't send if the request is over N input tokens (exact count for "
                            "Claude, else chars/4 estimate); exit 1 instead. Default: no limit")
    ai_group.add_argument('--dry-run-ai', action='store_true',
                       help='Build the AI request and print its size (exact token count for '
                            'Claude), then exit without calling the model')
    ai_group.add_argument('--no-fallback', action='store_true',
                       help='Claude: turn off server-side refusal fallback (on by default)')
    ai_group.add_argument('--api-key',
                       help='API key for chosen AI provider (visible in shell history and ps; '
                            'prefer ANTHROPIC_API_KEY / GOOGLE_API_KEY / OPENAI_API_KEY or --set-api-key)')
    ai_group.add_argument('--system-info', help='Path to JSON file containing system information')
    ai_group.add_argument('--compare', action='store_true',
                       help='Compare analyses from all configured AI providers')
    ai_group.add_argument('--deep-dive', nargs='*', metavar='N',
                       help='Deep dive on top issues (needs --ai). No args = prompt interactively after '
                            'analysis. Pass issue numbers to investigate just those, no prompt, e.g. --deep-dive 1 3')
                       
    config_group = parser.add_argument_group('configuration options')
    config_group.add_argument('--set-api-key', nargs='+', metavar=('PROVIDER', 'KEY'),
                          help='Store API key for provider (claude, gemini, chatgpt) in config.yaml. '
                               'Omit KEY or use "-" to type it at a hidden prompt '
                               '(a KEY on the command line is visible in shell history and ps)')
    config_group.add_argument('--show-config', action='store_true',
                          help='Show current configuration')
    config_group.add_argument('--reset-config', action='store_true',
                          help='Reset configuration to defaults (asks first, keeps a timestamped backup)')
    config_group.add_argument('--yes', action='store_true',
                          help='With --reset-config: do not ask for confirmation')
                          
    # Docker options
    docker_group = parser.add_argument_group('docker options')
    docker_group.add_argument('--docker', action='store_true',
                          help='Include Docker container logs')
    docker_group.add_argument('--container',
                          help='Specific container to analyze (default: all)')
    docker_group.add_argument('--no-container-stats', action='store_true',
                          help='Skip container stats collection')
    docker_group.add_argument('--docker-socket',
                          help='Path to Docker socket (default: /var/run/docker.sock)')

    # Windows Event Log options
    win_group = parser.add_argument_group('windows event log options')
    win_group.add_argument('--windows', action='store_true',
                       help='Analyze Windows Event Log on a remote host via WMI')
    win_group.add_argument('--win-host',
                       help='Windows host IP or hostname (required with --windows)')
    win_group.add_argument('--win-user', default='Administrator',
                       help='Windows username (default: Administrator)')
    win_group.add_argument('--win-password', default='',
                       help='Windows password (visible in shell history and ps; omit it to be prompted)')
    win_group.add_argument('--win-domain', default='',
                       help='Windows domain (leave blank for local accounts)')
    win_group.add_argument('--win-hashes',
                       help='NTLM hash auth in LM:NT format (alternative to password)')
    win_group.add_argument('--win-time',
                       choices=['hour', 'day', 'week', 'month', 'all'],
                       default='month',
                       help='How far back to look (default: month)')
    win_group.add_argument('--win-logs', nargs='+',
                       default=['System', 'Application', 'Security'],
                       metavar='LOG',
                       help='Event log channels to query (default: System Application Security)')
    win_group.add_argument('--win-level',
                       choices=['critical', 'error', 'warning', 'information', 'all'],
                       default='warning',
                       help='Minimum event level to collect (default: warning)')
    win_group.add_argument('--win-show-noisy', action='store_true',
                       help='Include events from known noisy/benign sources')
    win_group.add_argument('--win-max-events', type=int, default=5000,
                       help='Max events per log channel (default: 5000)')

    # Noise filters and baseline, kept per analyzed machine
    nb_group = parser.add_argument_group(
        'noise filter and baseline options (per analyzed machine: ~/.local/share/ai_logs/<target>/)')
    nb_group.add_argument('--noise-file', metavar='PATH',
                       help='Noise filter file (default: <target folder>/noise.yaml, read '
                            'automatically if it exists)')
    nb_group.add_argument('--no-noise-filter', action='store_true',
                       help='Ignore the noise filters for this run')
    nb_group.add_argument('--show-noise', action='store_true',
                       help='After the report, list every noise filter with the lines it skipped')
    nb_group.add_argument('--suggest-noise', nargs='?', const=10, type=positive_int, metavar='N',
                       help='After the report, print the top N patterns (default 10) as noise.yaml '
                            'entries to paste. Writes nothing (see --write-noise)')
    nb_group.add_argument('--write-noise', type=suggestion_choices, metavar='1,3|ID,ID',
                       help="With --suggest-noise: append exactly these suggestions (numbers from "
                            "this run's list, or the printed 6-character ids) to noise.yaml; "
                            "existing entries are kept, duplicates skipped")
    nb_group.add_argument('--save-baseline', action='store_true',
                       help="Save this run's patterns as the baseline (merged with the saved one)")
    nb_group.add_argument('--replace-baseline', action='store_true',
                       help='With --save-baseline: replace the saved baseline instead of merging')
    nb_group.add_argument('--no-baseline', action='store_true',
                       help='Ignore the saved baseline for this run (no NEW/SPIKE labels)')
    nb_group.add_argument('--baseline-info', action='store_true',
                       help='Print the baseline of the --local/--host target (path, saved_at, '
                            'pattern count, top patterns), then exit')
    nb_group.add_argument('--spike-factor', type=positive_float, default=5.0, metavar='X',
                       help='SPIKE = at least X times the baseline rate per minute, peak or mean '
                            '(--spike-vs) (default: 5)')
    nb_group.add_argument('--spike-min', type=positive_int, default=5, metavar='N',
                       help='... and at least N lines in this run (default: 5)')
    nb_group.add_argument('--spike-vs', choices=['peak', 'mean'], default='peak',
                       help="SPIKE compares this run's busiest bucket with the baseline's busiest "
                            '(peak, default), or the average rates (mean, the old way)')
    nb_group.add_argument('--baseline-bucket', type=positive_float, metavar='MIN',
                       help='With --save-baseline: bucket size in minutes for peak rates (default: '
                            "60, or the saved baseline's when merging)")
    nb_group.add_argument('--report-noise', action='store_true',
                       help='Print what the noise filters and the baseline did this run: per-filter '
                            'counts, top normal and NEW/SPIKE patterns with ids (read-only)')
    nb_group.add_argument('--ai-changes-only', action='store_true',
                       help='Send only NEW and SPIKE patterns to the AI; if there are none, skip '
                            'the AI call (exit 0). Needs a saved baseline')
    nb_group.add_argument('--list-targets', action='store_true',
                       help='Print hosts.json (which folder is which machine): folders, the names/IPs '
                            'used for each, short machine-id and SSH host key, last seen. Then exit')
    nb_group.add_argument('--rename-target', nargs=2, metavar=('OLD', 'NEW'),
                       help='Rename the folder OLD (or the folder of name/IP OLD) to NEW, in '
                            '~/.local/share/ai_logs/ and hosts.json; OLD stays a name for it. '
                            'Refuses if NEW exists. No connection. Then exit')

    return parser



def _render_md_table(lines: list) -> list:
    """Convert markdown pipe-table lines into aligned terminal output."""
    # Parse rows
    rows = []
    for line in lines:
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        rows.append(cells)

    # Remove separator row (all dashes)
    rows = [r for r in rows if not all(re.match(r'^[-:]+$', c) for c in r)]

    if not rows:
        return []

    # Calculate column widths
    ncols = max(len(r) for r in rows)
    rows  = [r + [''] * (ncols - len(r)) for r in rows]  # pad short rows
    widths = [max(len(r[i]) for r in rows) for i in range(ncols)]

    out = []

    for idx, row in enumerate(rows):
        cells = [row[i].ljust(widths[i]) for i in range(ncols)]
        line  = '  ' + ' │ '.join(cells)
        if idx == 0:
            out.append(Fore.CYAN + line + Style.RESET_ALL)
            out.append('  ' + '─┼─'.join('─' * w for w in widths))
        else:
            out.append(line)
    return out


def _format_section_body(body: str) -> list:
    """Format the body of one section, handling tables, bullets, code, numbered items."""
    out   = []
    lines = body.split('\n')
    i     = 0

    # Collect consecutive pipe-table lines
    table_buf = []

    def flush_table():
        if table_buf:
            out.extend(_render_md_table(table_buf))
            table_buf.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Markdown table row
        if stripped.startswith('|') and stripped.endswith('|'):
            table_buf.append(stripped)
            i += 1
            continue
        else:
            flush_table()

        if not stripped:
            i += 1
            continue

        # Horizontal rule — skip entirely
        if re.match(r'^[-*_]{3,}$', stripped):
            i += 1
            continue

        # Markdown headers (## Step 1, ### Details etc) — render as a plain label
        m_hdr = re.match(r'^#{1,4}\s+(.*)', stripped)
        if m_hdr:
            text = re.sub(r'\*\*(.*?)\*\*', r'\1', m_hdr.group(1))
            out.append(f"\n{Fore.CYAN}  {text}{Style.RESET_ALL}")
            i += 1
            continue

        # Blockquote lines (> text) — render as indented note
        if stripped.startswith('>'):
            text = re.sub(r'\*\*(.*?)\*\*', r'\1', stripped.lstrip('> ').strip())
            if text:
                out.append(f"{Fore.WHITE}{Style.DIM}  ▌ {text}{Style.RESET_ALL}")
            i += 1
            continue

        # Code block fence
        if stripped.startswith('```'):
            lang = stripped[3:].strip()
            i += 1
            code_lines = []
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing fence
            out.append(Fore.WHITE + Style.DIM + f'  ┌─ {lang or "code"} ' + '─' * max(0, 50 - len(lang)) + Style.RESET_ALL)
            for cl in code_lines:
                out.append(Fore.WHITE + Style.DIM + f'  │ {cl}' + Style.RESET_ALL)
            out.append(Fore.WHITE + Style.DIM + '  └' + '─' * 52 + Style.RESET_ALL)
            continue

        # Bullet
        if stripped.startswith(('-', '•', '*')) and not stripped.startswith('**'):
            text = re.sub(r'\*\*(.*?)\*\*', r'\1', stripped.lstrip('-•* '))
            out.append(f"{Fore.YELLOW}  • {text}{Style.RESET_ALL}")
            i += 1
            continue

        # Numbered item
        m = re.match(r'^(\d+)\.\s+(.*)', stripped)
        if m:
            num, text = m.group(1), m.group(2)
            text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
            out.append(f"{Fore.GREEN}  {num}. {text}{Style.RESET_ALL}")
            i += 1
            continue

        # Plain line — strip **bold** markers
        plain = re.sub(r'\*\*(.*?)\*\*', r'\1', stripped)
        out.append(f'  {plain}')
        i += 1

    flush_table()
    return out


def format_ai_recommendations(recommendations: Dict) -> str:
    """Format AI recommendations for clean terminal display."""
    output = []

    output.append('\n' + '=' * 70)
    output.append(f"{Fore.GREEN}🔍 AI Analysis Results{Style.RESET_ALL}")
    output.append('=' * 70)

    severity = str(recommendations.get('severity') or 'unknown').upper()
    sev_fmt = {
        'CRITICAL': (Fore.RED,    '🔴'),
        'HIGH':     (Fore.RED,    '🟠'),
        'MEDIUM':   (Fore.YELLOW, '🟡'),
        'LOW':      (Fore.GREEN,  '🟢'),
        'WARNING':  (Fore.YELLOW, '⚠️ '),
        'INFO':     (Fore.BLUE,   'ℹ️ '),
    }.get(severity, (Fore.WHITE, '❔'))
    # 'heuristic' = the reply stated no severity; ai_providers guessed from keywords
    how = ' (heuristic)' if recommendations.get('severity_source') == 'heuristic' else ''
    output.append(f"\n{sev_fmt[0]}Severity: {sev_fmt[1]} {severity}{how}{Style.RESET_ALL}")

    summary = recommendations.get('summary', '')
    if not summary:
        return '\n'.join(output)

    section_icons = {
        'Overall Assessment': '📊',
        'Critical Issues':    '🚨',
        'Service Issues':     '🔧',
        'Recommendations':    '💡',
        'Preventive Measures':'🛡️',
        # Deep dive sections
        'Root Cause':         '🔍',
        'Remediation Steps':  '🔧',
        'Verification':       '✅',
        'Documentation':      '📚',
        'Risks and Caveats':  '⚠️ ',
    }

    # Split on === markers
    parts = re.split(r'===\s*(.*?)\s*===', summary)
    # parts: [preamble, title1, body1, title2, body2, ...]
    if len(parts) < 3:
        # Fallback: just print raw
        for line in summary.split('\n'):
            output.append(f'  {line}')
        return '\n'.join(output)

    # Skip any preamble (parts[0])
    it = iter(parts[1:])
    for title in it:
        body = next(it, '')
        if not title.strip():
            continue
        icon = section_icons.get(title.strip())
        if icon is None:
            # Partial match for "Issue 1: Some Title", "Root Cause", etc.
            title_lower = title.strip().lower()
            for key, val in section_icons.items():
                if key.lower() in title_lower or title_lower.startswith(key.lower()[:6]):
                    icon = val
                    break
            else:
                icon = '📝'
        output.append(f"\n{Fore.CYAN}=== {icon} {title.strip()} ==={Style.RESET_ALL}")
        output.extend(_format_section_body(body))

    return '\n'.join(output)


def main():
    """Run the tool; with --status-file, write the result JSON afterwards, also
    when the run fails (exit 1 or 2, or an unexpected error = exit_code 1)."""
    code = 1
    try:
        _main()
        code = 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        raise
    finally:
        if RUN_STATUS.get('path'):
            write_status_file(RUN_STATUS['path'], code)


def _main():
    # The Windows branch below has its own `import getpass`, which made the name
    # local to main(): --host without --user and the --set-api-key prompt then
    # failed with UnboundLocalError. Declaring it global keeps one module name.
    global getpass
    parser = create_parser()
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
        
    args = parser.parse_args()
    RUN_STATUS.update(path=args.status_file, ai_requested=bool(args.ai or args.compare))
    
    # --no-color: also strip colour from main.py's own output (AI results)
    if args.no_color:
        colorama.deinit()
        colorama.init(strip=True)

    # Initialize config
    try:
        config = Config()
    except Exception as e:
        print(f"{Fore.RED}Error initializing config: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

    # Handle configuration commands
    if args.set_api_key:
        if len(args.set_api_key) > 2:
            parser.error('--set-api-key takes PROVIDER and at most one KEY')
        provider = args.set_api_key[0].lower()
        if provider not in AI_KEY_ENV:
            parser.error(f"unknown provider '{provider}' for --set-api-key (choose from {', '.join(AI_KEY_ENV)})")
        key = args.set_api_key[1] if len(args.set_api_key) == 2 else '-'
        if key == '-':
            key = getpass.getpass(f"API key for {provider} (input hidden): ").strip()
        if not key:
            print(f"{Fore.YELLOW}No key entered; nothing saved.{Style.RESET_ALL}")
            sys.exit(1)
        sys.exit(0 if config.set_api_key(provider, key) is not False else 1)
    
    if args.show_config:
        config.show_config()
        sys.exit(0)
        
    if args.reset_config:
        sys.exit(0 if config.reset_config(assume_yes=args.yes) is not False else 1)

    # hosts.json (which folder is which machine): show or rename, then exit; no connection
    if args.list_targets:
        text, status = target_store.list_targets()
        print(text)
        sys.exit(status)
    if args.rename_target:
        ok, msg = target_store.rename_target(*args.rename_target)
        print(msg if ok else f"{Fore.RED}{msg}{Style.RESET_ALL}", file=sys.stdout if ok else sys.stderr)
        sys.exit(0 if ok else 1)
    
    # Check arguments before any (slow) collection starts
    if args.host and not args.user:
        args.user = getpass.getuser()
    if args.docker and not args.host:
        parser.error('--docker requires --host (Docker logs are read over SSH)')
    if args.windows and not args.win_host:
        parser.error('--win-host is required when using --windows')
    if args.deep_dive is not None:
        if args.compare or not args.ai:
            parser.error('--deep-dive needs --ai PROVIDER and does not work with --compare')
        bad = [v for v in args.deep_dive if not v.isdigit()]
        if bad:
            parser.error(f"--deep-dive: not an issue number: {' '.join(bad)}")
    if args.dry_run_ai and not (args.ai or args.compare):
        parser.error('--dry-run-ai needs --ai PROVIDER or --compare')
    # Per-machine folder (noise.yaml, baseline): the machine being ANALYZED.
    # By name here; checked against hosts.json further down, after connecting
    target = (target_store.host_target(args.host) if args.host else
              target_store.local_target() if args.local else None)
    RUN_STATUS['target'] = target
    need = [o for o, on in (('--save-baseline', args.save_baseline), ('--baseline-info', args.baseline_info),
                            ('--ai-changes-only', args.ai_changes_only)) if on]
    if need and not target:
        parser.error(f"{need[0]} needs --local or --host (Windows has no baseline)")
    if args.no_baseline and need:
        parser.error(f"--no-baseline does not work with {need[0]}")
    if args.replace_baseline and not args.save_baseline:
        parser.error('--replace-baseline only works together with --save-baseline')
    if args.baseline_bucket and not args.save_baseline:
        parser.error("--baseline-bucket only works together with --save-baseline (a comparison "
                     "uses the saved baseline's bucket size)")
    if args.report_noise and not target:
        parser.error('--report-noise needs --local or --host')
    if args.ai_changes_only and not (args.ai or args.compare):
        parser.error('--ai-changes-only needs --ai PROVIDER or --compare')
    if args.write_noise and not args.suggest_noise:
        parser.error('--write-noise needs --suggest-noise (it picks from that list)')
    big = [c for c in (args.write_noise or []) if isinstance(c, int) and c > (args.suggest_noise or 0)]
    if big:
        parser.error(f"--write-noise {big[0]}: --suggest-noise lists only {args.suggest_noise}")
    if args.model and args.ai != 'claude' and not args.compare:
        parser.error('--model only applies to Claude (--ai claude, or --compare)')

    # AI key: --api-key, else env var, else config.yaml
    if args.ai:
        args.api_key = resolve_api_key(args.ai, config, args.api_key)
        if not args.api_key:
            print(f"\n{Fore.YELLOW}No API key found for {args.ai}. Pass --api-key, set "
                  f"{AI_KEY_ENV[args.ai]}, or store one (hidden prompt) with:{Style.RESET_ALL}")
            print(f"python3 main.py --set-api-key {args.ai}")
            sys.exit(1)

    # Claude model: --model, else claude_model in config.yaml, else Sonnet
    if (args.ai == 'claude' or args.compare) and not args.model:
        cfg = getattr(config, 'config', None)
        configured = cfg.get('claude_model') if isinstance(cfg, dict) else None
        try:
            args.model = claude_model(str(configured)) if configured else DEFAULT_CLAUDE_MODEL
        except argparse.ArgumentTypeError as e:
            parser.error(f"claude_model in {config.config_file}: {e}")

    # Which machine is this? Its folder comes from hosts.json (target_store.py):
    # --host connects here, before the baseline and noise.yaml are read, and
    # sends its machine-id and SSH host key (get_logs() reuses the connection);
    # --local reads its id locally. --baseline-info only looks the name up.
    collector = LogCollector(host=args.host, user=args.user, port=args.port, key_file=args.key)
    if target:
        try:
            ident = None if args.baseline_info else collector.identify()
        except KeyboardInterrupt:   # e.g. at the SSH key passphrase prompt
            print("\nAnalysis interrupted by user")
            sys.exit(1)
        target, notes = target_store.resolve_target(args.host or target, target, ident)
        for note in notes:
            colour = Fore.RED if note.startswith('WARNING') else Fore.YELLOW
            print(f"{colour}{note}{Style.RESET_ALL}", file=sys.stderr)
        RUN_STATUS['target'] = target
    baseline_path = bl.baseline_file(target, docker=args.docker) if target else None
    noise_path = (os.path.abspath(os.path.expanduser(args.noise_file)) if args.noise_file else
                  os.path.join(target_store.target_dir(target), 'noise.yaml') if target else None)

    # Per-machine data: --baseline-info, the saved baseline, the noise filters
    if args.baseline_info:
        text, status = bl.info_text(baseline_path)
        print(text)
        sys.exit(status)
    base = None
    if baseline_path and not args.no_baseline:
        base, err = bl.load_baseline(baseline_path)
        if err:
            print(f"{Fore.YELLOW}Baseline {baseline_path} not used: {err}{Style.RESET_ALL}",
                  file=sys.stderr)
    if args.ai_changes_only and base is None:
        print(f"{Fore.RED}--ai-changes-only: no usable baseline at {baseline_path}. Save one "
              f"first, at a quiet time, with --save-baseline.{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
    run_end = time.time()                      # this run's window: the last -t before now,
    run_start = int(run_end - args.time * 3600)   # whole seconds, like log show --start
    base_notes = []                            # overlap note: stderr, report, AI prompt
    if base is not None:
        if base.get('old_format'):
            print(f"{Fore.YELLOW}{bl.OLD_FORMAT_HINT}{Style.RESET_ALL}", file=sys.stderr)
        overlap = bl.overlap_minutes(base, run_start, run_end)
        if overlap:
            base_notes.append(bl.overlap_note(overlap))
            print(f"{Fore.YELLOW}Note: {base_notes[-1]}{Style.RESET_ALL}", file=sys.stderr)

    # Noise filters: noise.yaml is read automatically if it exists; one line says which
    noise, noise_line = nf.NoiseStats([]), None   # --quiet prints noise_line with the report
    if noise_path and args.no_noise_filter:
        noise_line = f"Noise filters: off (--no-noise-filter; {noise_path} not read)"
    elif noise_path:
        flist, warns, state = nf.load_noise_file(noise_path)
        for w in warns:
            print(f"{Fore.YELLOW}Noise filters: {w}{Style.RESET_ALL}", file=sys.stderr)
        if state == 'missing':
            noise_line = f"Noise filters: none ({noise_path} not found)"
        elif state == 'ok':
            noise_line = f"Noise filters: {noise_path} ({len(flist)} entries)"
        noise = nf.NoiseStats(flist)
    if noise_line and not args.quiet:
        print(noise_line)

    failed = False       # set when an AI, Windows or Docker step fails -> exit 1
    system_info = None   # extra context for the AI (Docker stats, --system-info)

    try:
        # The collector was set up above (with --host, identify() connected it)
        
        # Determine which severity levels to show
        show_levels = set(['error', 'warning', 'info'])
        
        # Handle exclusive filters
        if args.only_errors:
            show_levels = {'error'}
        elif args.only_warnings:
            show_levels = {'warning'}
        elif args.only_info:
            show_levels = {'info'}
            
        # Handle ignore filters
        if args.ignore:
            for level in args.ignore:
                # Convert 'warnings' to 'warning' if needed
                level = level.rstrip('s')
                if level in show_levels:
                    show_levels.remove(level)

        # macOS --local: only error/fault messages, unless every level is needed
        collector.mac_levels = 'all' if (args.all_levels or 'error' not in show_levels) else 'errors'
        collector.noise_filters = noise.filters   # macOS --local: also AND NOT (...) in log show

        # Create analyzer instance
        analyzer = LogAnalyzer(
            use_color=not args.no_color,
            output_file=args.output,
            output_json=args.json,
            show_full=args.full,
            debug=args.debug,
            show_levels=show_levels,
            ai_examples=args.max_examples
        )
        
        # Run standard log analysis (local or SSH — skip if Windows-only mode)
        run_local_scan = args.local or (args.host is not None)
        if not run_local_scan and not args.windows and not args.docker:
            print(f"{Fore.YELLOW}No scan target specified. Use --local, --host, --windows, or --docker.{Style.RESET_ALL}")
            parser.print_help()
            sys.exit(1)

        have_logs = False
        if run_local_scan:
            # Collect + analyze here instead of analyzer.run(), so the report is
            # printed once, below, after any Docker lines have been added.
            # get_logs() must run before Docker: it opens collector.ssh.
            if not args.quiet:
                print(f"Analyzing logs for the past {format_duration(args.time)}...")
            logs = collector.get_logs(args.time)
            noise.at_source = getattr(collector, 'noise_at_source', 0)
            if getattr(collector, 'last_error', None):
                failed = True   # get_logs() printed the command's own error on stderr
                print(f"{Fore.RED}Log collection failed (error above); nothing to analyze "
                      f"from this source.{Style.RESET_ALL}", file=sys.stderr)
            elif not logs:
                print("Warning: No logs were collected!"
                      + (" (noise filters were applied in log show)" if noise.at_source else ''))
            else:
                kept = nf.apply_filters(logs, noise)
                if not args.quiet:
                    print(f"Processing {len(kept)} log lines..."
                          + (f" ({len(logs) - len(kept):,} skipped by noise filters)" if len(kept) < len(logs) else ''))
                for line in kept:
                    analyzer.analyze_line(line)
                have_logs = True

        # Handle Docker logs if requested
        if args.docker:
            if not args.host:
                print(f"{Fore.RED}Error: Docker collection requires SSH host (--host){Style.RESET_ALL}")
                sys.exit(1)
                
            try:
                from docker_collector import RemoteDockerLogCollector
                docker_config = config.get_docker_config()
                
                # Update config with command line socket path if provided
                if args.docker_socket:
                    docker_config['socket'] = args.docker_socket
                
                # Use the existing SSH connection from the collector
                docker_collector = RemoteDockerLogCollector(collector.ssh, docker_config)
                
                # Get Docker logs
                docker_logs = docker_collector.get_container_logs(
                    hours=args.time,
                    container_name=args.container if args.container else None
                )
                
                if docker_collector.errors:
                    failed = True   # each failed `docker logs` was printed on stderr
                if not docker_logs:
                    print(f"{Fore.YELLOW}No Docker logs found{Style.RESET_ALL}")
                else:
                    # Get container stats if not disabled
                    container_stats = None
                    if not args.no_container_stats:
                        container_stats = docker_collector.get_container_stats(
                            container_name=args.container if args.container else None
                        )
                    
                    # Analyze Docker logs
                    for container, logs in docker_logs.items():
                        if not args.quiet:
                            print(f"\nAnalyzing logs for container: {container}")
                        for line in nf.apply_filters(logs, noise, kind='docker'):
                            analyzer.analyze_line(line)
                    have_logs = True
                        
                    # Add container stats to system info for AI analysis
                    if container_stats and (args.ai or args.compare):
                        if system_info is None:
                            system_info = {}
                        system_info['docker'] = container_stats
                        
            except Exception as e:
                failed = True
                print(f"{Fore.RED}Error collecting Docker logs: {str(e)}{Style.RESET_ALL}",
                      file=sys.stderr)
                if args.debug:
                    import traceback
                    traceback.print_exc()

        # Noise filter count and changes vs the baseline go at the top of the report
        if have_logs and noise.filters:
            analyzer.noise_summary = noise.summary()
            analyzer.report_notes.append(f"\nNoise filters: {analyzer.noise_summary}")
        changes = None   # "Changes vs baseline" lines (the report, --quiet)
        if have_logs and base is not None:
            analyzer.baseline_labels = bl.compare(analyzer.dedup, base, args.time * 60,
                                                  args.spike_factor, args.spike_min,
                                                  vs=args.spike_vs, start=run_start)
            changes = bl.changes_section(analyzer.dedup, analyzer.baseline_labels, base,
                                         args.spike_factor, args.spike_min, vs=args.spike_vs,
                                         notes=base_notes)
            analyzer.report_notes.append('')
            analyzer.report_notes.extend(changes)
            analyzer.baseline_note = ' '.join([bl.spike_note(base, args.spike_vs)]
                                              + [f"Note: {n}." for n in base_notes])

        # Print (or write to -o, without colour codes) the log report once
        if have_logs:
            status_counts(analyzer)
            report = (quiet_report(analyzer, noise_line, noise, changes) if args.quiet
                      else analyzer.format_output())
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(ANSI_RE.sub('', report))
            else:
                print(report)
            if args.show_noise:
                print('\n' + (noise.report() if noise.filters else 'Noise filters: none in use.'))
            if args.report_noise:
                labels = getattr(analyzer, 'baseline_labels', None) or {}
                rates = (bl.run_rates(analyzer.dedup, base, args.time * 60, args.spike_vs, run_start)
                         if base is not None else {})
                print('\n' + noise_report(analyzer, noise, noise_line, base, labels, rates, args.spike_vs,
                                          getattr(collector, 'own_lines_dropped', 0)))
            if args.suggest_noise:
                text, entries, by_id = nf.suggest(analyzer.dedup, args.suggest_noise, noise_path,
                                                  window=format_duration(args.time), target=target)
                print('\n' + text)
                if args.write_noise and write_noise(args.write_noise, entries, noise_path, by_id):
                    failed = True
            if args.save_baseline:
                if not analyzer.dedup.patterns:
                    print("No patterns in this run; baseline not saved.")
                else:
                    try:
                        print(bl.save_baseline(baseline_path, analyzer.dedup, target,
                                               'docker' if args.docker else 'system',
                                               args.time * 60, replace=args.replace_baseline,
                                               bucket_minutes=args.baseline_bucket,
                                               start=run_start, end=run_end))
                    except (OSError, RuntimeError) as e:
                        failed = True
                        print(f"{Fore.RED}Baseline not saved: {e}{Style.RESET_ALL}", file=sys.stderr)
        else:
            if args.quiet and noise_line:
                print(noise_line)
            if args.suggest_noise or args.save_baseline:
                print(f"{Fore.YELLOW}No log lines were analyzed: nothing to suggest or save.{Style.RESET_ALL}")

        # Run Windows Event Log analysis if requested
        if args.windows:
            if not args.win_host:
                print(f"{Fore.RED}Error: --win-host is required when using --windows{Style.RESET_ALL}")
                sys.exit(1)

            if not args.win_password and not args.win_hashes:
                import getpass
                args.win_password = getpass.getpass(f"Windows password for {args.win_user}@{args.win_host}: ")

            try:
                from windows_collector import WindowsEventCollector
                from windows_analyzer import WindowsLogAnalyzer

                print(f"\n{Fore.CYAN}Connecting to {args.win_host} via WMI...{Style.RESET_ALL}")

                win_collector = WindowsEventCollector(
                    host=args.win_host,
                    username=args.win_user,
                    password=args.win_password,
                    domain=args.win_domain or '',
                    hashes=args.win_hashes,
                )

                with win_collector:
                    # Detect OS via SMB (fast, works before full WMI auth)
                    os_caption = ''
                    try:
                        os_caption = win_collector.detect_os()
                        if os_caption:
                            print(f"{Fore.CYAN}Target OS: {os_caption}{Style.RESET_ALL}")
                    except Exception:
                        pass

                    print(f"{Fore.CYAN}Collecting {args.win_time} of events "
                          f"(level >= {args.win_level}) from: "
                          f"{', '.join(args.win_logs)}{Style.RESET_ALL}")

                    events = win_collector.get_events(
                        logs=args.win_logs,
                        time_window=args.win_time,
                        level=args.win_level,
                        max_events_per_log=args.win_max_events,
                    )

                    print(f"{Fore.GREEN}Collected {len(events)} events.{Style.RESET_ALL}")

                    win_analyzer = WindowsLogAnalyzer(
                        use_color=not args.no_color,
                        show_full=args.full,
                    )
                    win_analyzer._os_caption = os_caption
                    findings = win_analyzer.analyze(events)
                    win_analyzer.print_report(
                        findings,
                        hide_noisy=not args.win_show_noisy,
                    )

                    # Feed into AI analysis if requested
                    if args.ai or args.compare:
                        # Inject Windows summary into analyzer results
                        win_summary = win_analyzer.get_results_for_ai(
                            max_examples=args.max_examples
                        )
                        # Append to the existing analyzer results
                        analyzer._windows_summary = win_summary

            except ImportError as e:
                failed = True
                print(f"{Fore.RED}Windows support could not be loaded: {e}{Style.RESET_ALL}")
                print("It needs windows_collector.py / windows_analyzer.py next to main.py, and impacket (pip install impacket)")
                if args.debug:
                    import traceback; traceback.print_exc()
            except Exception as e:
                failed = True
                print(f"{Fore.RED}Windows collection error: {e}{Style.RESET_ALL}")
                if args.debug:
                    import traceback; traceback.print_exc()


        # --ai-changes-only: nothing new or spiking = nothing to ask the AI
        if ((args.ai or args.compare) and args.ai_changes_only and have_logs
                and not getattr(analyzer, 'baseline_labels', None)
                and not getattr(analyzer, '_windows_summary', None)):
            print("No new or spiking patterns vs baseline - AI call skipped")
            RUN_STATUS['ai_skipped_reason'] = 'no NEW/SPIKE patterns vs baseline'
            sys.exit(1 if failed else 0)

        # Run AI analysis if requested
        if args.ai or args.compare:
            valid_providers = ['claude', 'gemini', 'chatgpt']
            
            if args.ai and args.ai.lower() not in valid_providers:
                print(f"\n{Fore.RED}Error: Invalid AI provider. Choose from: {', '.join(valid_providers)}{Style.RESET_ALL}")
                sys.exit(1)
            
            # Get API key from config if not provided in command line
            if args.ai and not args.api_key:
                args.api_key = config.get_api_key(args.ai.lower())
                if not args.api_key:
                    print(f"\n{Fore.YELLOW}No API key found for {args.ai}. Set it with:{Style.RESET_ALL}")
                    print(f"python main.py --set-api-key {args.ai} your-key-here")
                    sys.exit(1)
            
            try:
                # Load system info if provided
                if args.system_info:
                    try:
                        with open(args.system_info) as f:
                            if system_info is None:
                                system_info = json.load(f)
                            else:
                                system_info.update(json.load(f))
                    except Exception as e:
                        print(f"{Fore.YELLOW}Error loading system info: {str(e)}{Style.RESET_ALL}")

                if args.compare:
                    # Run analysis with all providers
                    results = {}
                    for provider in valid_providers:
                        try:
                            # Get API key for each provider (env var, else config.yaml)
                            provider_key = resolve_api_key(provider, config)
                            if not provider_key:
                                print(f"{Fore.YELLOW}Skipping {provider}: No API key found "
                                      f"(set {AI_KEY_ENV[provider]} or use --set-api-key){Style.RESET_ALL}")
                                continue
                                
                            ai_provider = get_ai_provider(provider, provider_key, model=args.model,
                                                          fallback=not args.no_fallback)
                            if not args.quiet:
                                print(f"\nRunning analysis with {provider.title()}...")
                            _lr = analyzer.get_results(args.summary)
                            if args.windows and not (args.local or args.host):
                                _ws = getattr(analyzer, '_windows_summary', '')
                                if _ws:
                                    _lr = _ws
                            _has_data = (
                                (isinstance(_lr, str) and _lr.strip()) or
                                (isinstance(_lr, dict) and (
                                    _lr.get('stats', {}).get('total_lines', 0) > 0 or
                                    _lr.get('_windows_summary')
                                ))
                            )
                            if not _has_data:
                                print(f"{Fore.YELLOW}Skipping {provider}: no log data collected.{Style.RESET_ALL}")
                                continue
                            _lr, _in_size = prepare_ai_logs(analyzer, _lr, system_info, args,
                                                            provider, ai_provider)
                            if over_token_limit(args, _in_size):
                                failed = True
                                continue
                            if args.dry_run_ai:
                                continue
                            RUN_STATUS['ai_called'] = True
                            results[provider] = ai_provider.analyze_logs(
                                _lr,
                                system_info
                            )
                            status_ai(results[provider])
                        except Exception as e:
                            failed = True
                            print(f"Error with {provider}: {str(e)}")

                    if args.dry_run_ai:
                        RUN_STATUS['ai_skipped_reason'] = '--dry-run-ai'
                        print("--dry-run-ai: requests built; no AI model was called.", file=sys.stderr)
                        sys.exit(1 if failed else 0)

                    # Print comparison
                    if results:
                        print("\n=== AI Analysis Comparison ===")
                        for provider, result in results.items():
                            print(f"\n{provider.title()} Analysis:")
                            print(format_ai_recommendations(result))
                    else:
                        print(f"\n{Fore.YELLOW}No AI analysis results available{Style.RESET_ALL}")
                else:
                    # Run analysis with single provider
                    try:
                        ai_provider = get_ai_provider(args.ai, args.api_key, model=args.model,
                                                      fallback=not args.no_fallback)
                        if not args.quiet:
                            print(f"\nRunning AI analysis using {args.ai.title()}...")

                        # Build log data: prefer Windows summary when that's the only source
                        log_results = analyzer.get_results(args.summary)
                        win_only = args.windows and not (args.local or args.host)
                        if win_only:
                            win_sum = getattr(analyzer, '_windows_summary', '')
                            if win_sum:
                                log_results = win_sum  # pass the text summary directly

                        # Determine whether there's actually anything to send
                        has_local = (
                            isinstance(log_results, dict)
                            and log_results.get('stats', {}).get('total_lines', 0) > 0
                        )
                        has_windows = bool(
                            getattr(analyzer, '_windows_summary', '') or
                            (isinstance(log_results, str) and log_results.strip())
                        )

                        if not has_local and not has_windows:
                            RUN_STATUS['ai_skipped_reason'] = 'no log data collected'
                            print(f"{Fore.YELLOW}No log data collected — skipping AI analysis.{Style.RESET_ALL}")
                        else:
                            log_results, n_in = prepare_ai_logs(analyzer, log_results, system_info,
                                                                args, args.ai, ai_provider)
                            if over_token_limit(args, n_in):
                                RUN_STATUS['ai_skipped_reason'] = 'over --max-input-tokens'
                                sys.exit(1)
                            if args.dry_run_ai:
                                RUN_STATUS['ai_skipped_reason'] = '--dry-run-ai'
                                print("--dry-run-ai: request built; the AI model was not called.",
                                      file=sys.stderr)
                                sys.exit(1 if failed else 0)

                            # Get AI recommendations
                            RUN_STATUS['ai_called'] = True
                            recommendations = ai_provider.analyze_logs(
                                log_results,
                                system_info
                            )
                            status_ai(recommendations)
                            if args.debug and getattr(ai_provider, 'last_usage', None):
                                print(f"DEBUG: usage {ai_provider.last_usage}")

                            # Print formatted recommendations
                            formatted = format_ai_recommendations(recommendations)
                            print(formatted)

                            # Save to file if output is specified (without colour codes)
                            if args.output:
                                with open(args.output, 'a') as f:
                                    f.write('\n' + ANSI_RE.sub('', formatted))

                            # Deep dive — interactive or auto
                            if args.ai and (args.deep_dive is not None):
                                from ai_providers import deep_dive_issues
                                summary_text = recommendations.get('summary', '')

                                # Seed the first round: CLI numbers if given, else ask
                                if args.deep_dive:
                                    pending = []
                                    for v in args.deep_dive:
                                        try: pending.append(int(v))
                                        except ValueError: pass
                                else:
                                    pending = None  # signal: ask interactively first

                                def _prompt_issues():
                                    """Print the menu and return a list of ints, or [] to exit."""
                                    print(f"\n{Fore.CYAN}{'─'*70}")
                                    print(f"🔬 Deep Dive — Enter issue numbers to investigate")
                                    print(f"   (e.g.  1    or  1 3    or  all   — Enter to finish)")
                                    print(f"{'─'*70}{Style.RESET_ALL}")
                                    try:
                                        raw = input("  Issues: ").strip().lower()
                                    except (EOFError, KeyboardInterrupt):
                                        return []
                                    if not raw or raw in ('q', 'quit', 'exit', 'done', 'n', 'no'):
                                        return []
                                    if raw == 'all':
                                        return list(range(1, 6))
                                    return [int(x) for x in raw.split() if x.isdigit()]

                                def _run_dive(issue_nums):
                                    """Execute one deep dive and print/save results."""
                                    nonlocal failed
                                    print(f"\n{Fore.CYAN}Running deep dive on issue(s): "
                                          f"{issue_nums}...{Style.RESET_ALL}\n")
                                    try:
                                        dive_text = deep_dive_issues(
                                            ai_provider, issue_nums, summary_text,
                                            # interactive: later rounds can read the cached prefix
                                            cache=pending is None
                                        )
                                        if args.debug and getattr(ai_provider, 'last_usage', None):
                                            print(f"DEBUG: usage {ai_provider.last_usage}")
                                        print(f"\n{'='*70}")
                                        print(f"{Fore.GREEN}🔬 Deep Dive — Issue(s): "
                                              f"{', '.join(str(n) for n in issue_nums)}"
                                              f"{Style.RESET_ALL}")
                                        print(f"{'='*70}")
                                        if '===' in dive_text:
                                            print(format_ai_recommendations(
                                                {'summary': dive_text, 'severity': 'info'}
                                            ))
                                        else:
                                            for line in _format_section_body(dive_text):
                                                print(line)
                                        if args.output:
                                            with open(args.output, 'a') as f:
                                                nums_str = ', '.join(str(n) for n in issue_nums)
                                                f.write(f'\n\n=== Deep Dive (Issue(s): {nums_str}) ===\n'
                                                        + dive_text)
                                    except Exception as de:
                                        failed = True
                                        print(f"{Fore.RED}Deep dive error: {de}{Style.RESET_ALL}")
                                        if args.debug:
                                            import traceback; traceback.print_exc()

                                if pending is not None:
                                    # Numbers given on the command line: investigate those, then stop
                                    _run_dive(pending)
                                else:
                                    # Interactive: ask, run, keep asking until user quits
                                    issue_nums = _prompt_issues()
                                    while issue_nums:
                                        _run_dive(issue_nums)
                                        issue_nums = _prompt_issues()
                                    print(f"\n{Fore.CYAN}Deep dive session ended.{Style.RESET_ALL}")

                    except Exception as e:
                        failed = True
                        print(f"Error with {args.ai}: {str(e)}")
                        if args.debug:
                            import traceback
                            traceback.print_exc()
                            
            except ImportError as e:
                print(f"\n{Fore.YELLOW}Required packages missing. Install with:{Style.RESET_ALL}")
                print("pip install anthropic google-genai openai")
                sys.exit(1)
                
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    sys.exit(1 if failed else 0)
                
if __name__ == "__main__":
    main()
