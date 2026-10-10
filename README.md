# AI Log Analyzer

Analyze system logs from local or remote Mac, Linux, and **Windows** hosts,
with optional AI-powered summarization.

## Installation

```bash
pip install -r requirements.txt
```

> For Windows support, `impacket` must be installed (included in requirements).

## Quick Start

```bash
# Local macOS/Linux — last 15 minutes, the default  (--local is now required to scan local machine)
python main.py --local

# Local logs, last 2 hours, errors only  (-t: 90s, 15m, 2h, 1d, 1h30m; bare number = hours)
python main.py --local -t 2h --only-errors

# Remote Linux over SSH — last 6 hours, errors only
python main.py -t 6 --host 10.0.0.10 --user root --key ~/.ssh/id_ed25519 --only-errors

# Remote Windows via WMI — last month (default), warnings and above
python main.py --windows --win-host 192.168.1.50 --win-user Administrator

# Remote Windows — last day, errors only, specific logs
python main.py --windows --win-host 192.168.1.50 --win-user Administrator \
               --win-time day --win-level error --win-logs System Application

# Remote Windows — all time (use carefully on busy hosts)
python main.py --windows --win-host 192.168.1.50 --win-user Administrator \
               --win-time all --win-level error

# Combine Windows analysis with AI
python main.py --windows --win-host 192.168.1.50 --win-user Administrator \
               --ai claude
```

## Windows Setup Requirements

On the **target Windows host**:
1. WMI service must be running: `services.msc` → "Windows Management Instrumentation"
2. Remote WMI must be allowed through the firewall:
   ```
   netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes
   ```
3. User account must be in **Administrators** or **Event Log Readers** group
4. DCOM must be enabled (it is by default on all modern Windows versions)

## Windows Options

| Flag | Default | Description |
|------|---------|-------------|
| `--windows` | — | Enable Windows Event Log mode |
| `--win-host` | — | Target host IP or hostname (required) |
| `--win-user` | Administrator | Username |
| `--win-password` | (prompted) | Password |
| `--win-domain` | (local) | Domain name |
| `--win-hashes` | — | NTLM hash auth `LM:NT` (alternative to password) |
| `--win-time` | month | Time window: `hour`, `day`, `week`, `month`, `all` |
| `--win-logs` | System Application Security | Log channels to query |
| `--win-level` | warning | Min level: `critical`, `error`, `warning`, `information`, `all` |
| `--win-max-events` | 5000 | Max events per log channel |
| `--win-show-noisy` | — | Include events from known noisy sources |

## AI Configuration

```bash
# Save API keys (stored in ~/.config/ai_logs/config.yaml)
python main.py --set-api-key claude sk-ant-...
python main.py --set-api-key chatgpt sk-...
python main.py --set-api-key gemini AI...

# Use AI analysis
python main.py --local -t 15m --ai claude
python main.py --windows --win-host 10.0.0.5 --ai claude

# See the size (exact tokens for Claude) without calling the model
python main.py --local -t 1h --ai claude --dry-run-ai
```

## Time window and what is sent to the AI

- `-t/--time` sets how far back local/SSH/Docker logs go: `90s`, `15m`, `2h`,
  `1d` or `1h30m` (any case; `m` = minutes). A bare number still means hours
  (`-t 6` = 6 hours). Default: `15m`. Windows uses `--win-time` instead.
  Remote hosts get a relative window (`journalctl --since '900s ago'`,
  `docker logs --since 900s`), so their own time zone doesn't shift it.
- Before anything goes to the AI, matched lines are grouped into patterns
  (timestamps, PIDs, numbers, hex IDs, UUIDs, IPs, MACs, durations and
  quoted paths masked). Each pattern is sent once with its count, first/last
  time and `--max-examples` raw example line(s) (default 1), errors first,
  then by count. `--ai-max-chars N` (default 12000) caps the size: the
  lowest-priority patterns are dropped first and the prompt says how many.
- A one-line summary on stderr comes before each AI call: lines, patterns,
  chars, and input tokens (exact for Claude via the free `count_tokens`
  endpoint, otherwise an estimate of chars/4).
- `--max-input-tokens N`: don't send if the request is bigger; exit 1 with
  hints. `--dry-run-ai`: build the request, print the summary, exit 0
  without calling the model (still needs an API key).

## macOS log levels (`--local` on a Mac)

- By default only real errors and faults are fetched:
  `log show --style ndjson --predicate '(logType == "error" OR logType == "fault")'`.
  Faults are shown as `[FAULT]` and errors as `[ERROR]` (in "Changes vs
  baseline", `--quiet`, `--report-noise`, `--suggest-noise`, `--baseline-info`
  and the AI digest). These are the macOS log levels, not a judgement of how
  serious a line is; the AI is told so. Faults still sort first. Process names
  keep their spaces (`Bartender 6`), and the `log` process's note about the
  tool's own `log show` run is dropped.
- `--all-levels` brings back the old keyword filter (any message mentioning
  error/warning/failure/failed, or process `system`): much noisier.
  `--only-warnings`, `--only-info` and `--ignore errors` imply it.
- Local Linux, SSH and Docker are unchanged (no level filter). For journald
  the equivalent would be `journalctl -p warning` (priorities 0-4,
  emerg..warning); not done yet.
- "Total matches found: N lines" and the AI line's "N matched" are the same
  count. The AI's severity badge comes from its own `SEVERITY:` first line;
  "(heuristic)" means the reply had none and a keyword guess is shown.
- A failed collection (`log show` refused, SSH or `docker` error, non-zero
  exit) prints the real error on stderr and exits 1. "No logs were
  collected" means the command worked and found nothing (exit 0).

## Noise filters and baselines (per analyzed machine)

Both live in one folder per machine being **analyzed** (not the one running
the script): `~/.local/share/ai_logs/<target>/`, folder mode 700, files 600.

- `<target>` for `--local`: this Mac's LocalHostName from the network prefs
  plist (else the host name), lower-case, domain removed, e.g. `andromeda`. For
  `--host H`: H as typed, lower-case, a trailing `.local` removed, unsafe
  characters replaced by `_`. So `--host andromeda.local` uses the same folder
  as `--local` on andromeda, and `--host server1.example.com` uses
  `server1.example.com/`. `--host H --docker` uses H's folder and noise.yaml.
- **`noise.yaml`** (or `--noise-file PATH`) is read automatically if it exists.
  Every run prints `Noise filters: <path> (M entries)` or
  `Noise filters: none (<path> not found)`. It is a plain YAML list, e.g.
  `~/.local/share/ai_logs/andromeda/noise.yaml`:

```yaml
- process: "WindowServer"
  message: "_CGXPackagesSetWindowConstraints: Invalid window"
  note: "window redraw noise, up to 146/min"
- subsystem: "com.apple.network"
  message: "nw_protocol"
  note: "network/QUIC chatter (nsurlsessiond, dataaccessd, mDNSResponder)"
- process: "dasd"
  message: "Skipping activity"
- process: "searchpartyd"
  message: "No BeaconStoreActor available"
```

  Keys: `process` and `subsystem` (exact names, case-sensitive), `message`
  (text anywhere in the message, any case), optional `source: docker` or
  `source: system` (only Docker lines / only the system log), optional
  `note`. Every key given must match. A bad entry (unknown key, empty,
  wrong type) is skipped with a warning; the run goes on.
- Matching lines are dropped before the report, the AI digest and the
  baseline. The report and the AI size line say `N lines skipped by M noise
  filters`. On macOS `--local` the first 100 entries also go into the
  `log show` predicate, e.g. `(logType == "error" OR logType == "fault") AND
  NOT (process == "WindowServer" AND eventMessage CONTAINS[c] "...")`, so
  that noise isn't even fetched. Those lines can't be counted, so the line
  says `(macOS: filtered at source, not counted)`. Linux, SSH and Docker
  lines have no subsystem, and `message` is matched against the whole line.
- `--no-noise-filter`: ignore the file for one run. `--show-noise`: every
  entry with the lines it skipped after collection.
- `--suggest-noise [N]` (default 10): after a normal run, prints the top N
  patterns as entries to paste (process, subsystem if known, the longest
  fixed text of the message cut to about 60 characters, and a `note` with
  the count and "inferred benign? check it"), with the exact noise.yaml
  path. It writes nothing. `--suggest-noise --write-noise 3fa2c1,1b9e07`
  appends exactly the suggestions you name (the printed 6-character ids are
  the same from run to run; plain numbers refer to that run's own list).
  Existing text is kept, duplicates are skipped, the write is atomic.
  Patterns that give the same process, subsystem and message are merged
  into one suggestion with the counts added up. An id works even if that
  suggestion is not in the top N of the run (e.g. an id from `--report-noise`).
- **Baseline**: `--save-baseline` saves this run's patterns to
  `baseline.json` (`baseline-docker.json` for `--host H --docker` runs, which
  mix the host's journal and the container lines). It is merged with the
  saved one (all patterns kept, highest peak, counts added up) unless
  `--replace-baseline`; the first save says "Baseline created". Each
  pattern's lines are counted per time bucket (60 minutes, `--baseline-bucket
  MIN`, counted from the start of the window): the busiest bucket gives the
  pattern's **peak rate** (lines per minute), stored with its average
  (`mean_rate`). Later runs label each pattern `[NEW]` (not in the
  baseline) or `[SPIKE xR]`: this run's busiest bucket (same bucket size; a
  run shorter than one bucket uses its average) is at least `--spike-factor`
  (5) times the baseline peak, and the pattern has at least `--spike-min`
  (5) lines. So a burst that happens every day (wake, unlock) stays normal,
  instead of showing up as `SPIKE x12.0` in a 2-hour run against a 24-hour
  average. `--spike-vs mean` brings back the old average-against-average
  comparison. Lines without a readable time count, but not toward the peak.
  A baseline saved before this change (no peak) still works: one hint line
  says to rebuild it with `--replace-baseline`, and it is compared as before.
  If this run's window overlaps the baseline's window, a note says so (on
  stderr, in the report and in the AI prompt). The report
  starts with "Changes vs baseline"; the AI digest lists NEW, then SPIKE,
  then the rest within each severity and explains the labels in one line.
  `--ai-changes-only` sends only NEW and SPIKE patterns (the header says how
  many normal ones were left out); with none it prints `No new or spiking
  patterns vs baseline - AI call skipped` and exits 0. `--no-baseline`
  ignores it for a run; `--baseline-info` prints the path, saved_at, the
  window, the bucket size, the pattern count and the top patterns by peak.
- **Short output**: `--quiet` prints only the noise filter line, the
  "Changes vs baseline" section (without a baseline: the totals and the top
  10 patterns), and the AI result (or the "AI call skipped" line). The `-o`
  file gets the same; stderr, exit codes and the AI request don't change.
- **Noise report**: `--report-noise` prints what the filters and the
  baseline did in this run: each filter's match count ("at source, not
  counted" for the ones macOS applies in `log show`), the top 10 normal
  patterns with their rate against the baseline peak, and the top 10
  NEW/SPIKE ones, each with the id to use with `--suggest-noise
  --write-noise ID`. It writes nothing and calls no AI unless you add `--ai`.
- Lines in "Changes vs baseline" and in the noise report that would read the
  same (same label, level, process, shortened text and id) are shown once,
  with the counts summed and "(N patterns)" at the end. Display only: the
  baseline and the NEW/SPIKE counts still count each pattern.
- **Status file for automation**: `--status-file PATH` writes, after the run
  (also when it fails), a small JSON: `time`, `target`, `severity`
  (low/medium/high/critical or null), `severity_source` (ai/heuristic/null),
  `ai_called`, `ai_skipped_reason`, `new`, `spike`, `lines`, `patterns`,
  `exit_code`. Mode 600; the folder is created (700) if missing. An hourly
  launchd job that reads it is described in the Script Wrangler report
  folder (`launchd/INSTALL.md`).
- On macOS `--local`, log lines from the tool's own process and from its
  `log show` child (exact pid) are dropped.
- **Baselines are sensitive.** The templates are masked (numbers, IDs, IPs,
  paths with digits), but can still contain host names, user names and
  paths. They are mode 600 in a 700 folder; don't share or commit them.
- Nothing here is ever deleted. A failed write leaves a `.tmp` file in the
  folder and says so.

Suggested workflow (Mac `andromeda`):

1. `python3 main.py --local -t 5m --suggest-noise` and read the list.
2. Paste the entries you agree with into
   `~/.local/share/ai_logs/andromeda/noise.yaml`, or let the next run append
   them by id: `python3 main.py --local -t 5m --suggest-noise --write-noise 3fa2c1,1b9e07`.
3. Build the baseline from a whole day: `python3 main.py --local -t 24h --save-baseline --replace-baseline`
   (24 hours of a Mac took about 3 minutes and 2.9 MB).
4. A few hours later (so the windows don't overlap):
   `python3 main.py --local -t 2h --ai claude --ai-changes-only --quiet`.
   `--report-noise` shows what is normal, what changed, and the ids to filter.

## Proxmox LXC containers (`--guest`)

On a Proxmox host, ai_logs can read the journal of each LXC container
through the host, with `pct exec`: no SSH keys or network access into the
containers are needed, but `--user` must be root on the host.

```bash
# One container (id from `pct list`)
python3 main.py --host halley.root-cervers.net --user root --key ~/.ssh/id_rsa_ansible --guest 48253 -t 1h --quiet

# Every running container, one after another (same options for each)
python3 main.py --host halley.root-cervers.net --user root --key ~/.ssh/id_rsa_ansible --guest all -t 1h --save-baseline --quiet
python3 main.py --host halley.root-cervers.net --user root --key ~/.ssh/id_rsa_ansible --guest all -t 1h --ai-changes-only --ai claude --quiet
```

- Each container is its own target: hosts.json name `HOST/ctID`, matched by
  the container's machine-id, folder named after its host name (`pihole`,
  `vatican`, ...; else `HOST-ctID`). So it has its own `noise.yaml` and
  baseline. If you later SSH to the same container directly, the
  machine-id finds the same folder.
- `--guest all` lists running containers (`pct list`) and runs main.py once
  per container, with a `===== HOST CT ID (name) =====` header each. Exit 1
  if any of them failed (e.g. a container without journald).
- The SSH host key check is the Proxmox host's. Run the host once without
  `--guest` first so its key is recorded; a changed key is accepted on a
  run without `--guest`.
- A run with no matched patterns (a quiet container) now saves a 0-pattern
  baseline, so `--ai-changes-only` works for it: any pattern later is NEW.
- Not with `--docker`; `--guest all` not with `-o` or `--status-file`.
- VMs are not covered (they need the QEMU guest agent or plain SSH).

## Claude options

- `--model`: `sonnet` (default, `claude-sonnet-5-5`), `opus`
  (`claude-opus-5-5`), `haiku` (`claude-haiku-5-5`), or any full ID starting
  with `claude-`. Without `--model`, `claude_model:` in config.yaml is used if
  set. The model is shown in the summary line. Gemini/ChatGPT are unchanged.
- Refusal fallback: on by default, `--no-fallback` to disable. A refusal
  (`stop_reason: refusal`, which security logs can trigger) is reported with
  its category and makes the run exit 1. If the installed `anthropic` package
  doesn't support the fallback option, a one-line note is printed and the call
  is retried once without it.
- Interactive `--deep-dive` rounds mark the earlier analysis for prompt caching,
  so the 2nd and later rounds within 5 minutes read it at a lower price.
  `--deep-dive 1 3` (one round) and plain runs don't use caching.
  `--debug` prints each response's token usage, including cache reads.

## Output Options

| Flag | Description |
|------|-------------|
| `--full` | Show full messages without truncation |
| `--json` | Output as JSON |
| `-o FILE` | Write output to file |
| `--quiet` | Only the noise line, changes vs baseline (or top 10 patterns), AI result |
| `--status-file PATH` | After the run, write a JSON result (severity, NEW/SPIKE, exit code) for scripts |
| `--debug` | Show debug/traceback info |
| `--only-errors` | Show errors only |
| `--only-warnings` | Show warnings only |
| `--no-color` | Disable colored output |

## Architecture

```
main.py              — CLI entry point, argument parsing
collector.py         — Mac/Linux log collection (local + SSH)
windows_collector.py — Windows Event Log via WMI/DCOM
analyzer.py          — Pattern-based log analysis (Mac/Linux)
windows_analyzer.py  — Windows Event ID database + analysis
ai_providers.py      — Claude / ChatGPT / Gemini integration
ai_analyzer.py       — AI prompt building
local_insights.py    — Local pattern insights
docker_collector.py  — Docker container log collection
noise_filters.py     — noise.yaml filters, --suggest-noise / --write-noise
baseline.py          — saved baseline (peak + mean rates), NEW / SPIKE labels
target_store.py      — per-machine folder ~/.local/share/ai_logs/<target>/
config.py            — Configuration management
```
