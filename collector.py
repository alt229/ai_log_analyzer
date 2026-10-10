# collector.py
# History:
# 2026-10-09 - Script Wrangler: the SSH host key is checked during the
#   handshake, before login (HostKeyCheck replaces AutoAddPolicy): known
#   from ~/.ssh/known_hosts (read only) or hosts.json -> go on; unknown ->
#   accepted with a note; CHANGED -> ssh-style warning, HostKeyRefused, no
#   login, no command (unless --accept-hostkey-change) (hostkey.patch).
# 2026-10-09 - Script Wrangler: identify() says which machine a host is
#   (machine-id / macOS IOPlatformUUID via one extra SSH command, plus the
#   SSH host key fingerprint) for hosts.json (target_store.py). A failed
#   SSH connection is remembered: get_logs() raises the same error instead
#   of connecting again (hostid.patch).
# 2026-10-09 - Script Wrangler: SSH keys load again on paramiko 4+ (it removed
#   DSSKey, which made every key type fail); DSS keys are tried only if the
#   installed paramiko still has DSSKey.
import base64
import hashlib
import inspect
import subprocess
from datetime import datetime, timedelta
import paramiko
from typing import List, Optional
import platform
import os
import sys
import json

# macOS `log show` predicates. Default: only real errors and faults (field
# `logType`, as listed by `log help predicates`). --all-levels: the old
# keyword filter, which also catches ordinary messages that merely mention
# "error", "warning", "failed" etc.
MAC_LEVEL_PREDICATE = '(logType == "error" OR logType == "fault")'
MAC_KEYWORD_PREDICATE = '(eventMessage CONTAINS[c] "error" OR eventMessage CONTAINS[c] "warning" OR eventMessage CONTAINS[c] "failure" OR eventMessage CONTAINS[c] "failed" OR process == "system")'
# macOS log type -> analyzer/dedup severity (other types: decided by keywords)
MAC_LEVELS = {'fault': 'critical', 'error': 'error'}
# identify(): the ONE extra remote command. Linux: the machine-id file; macOS:
# ioreg's IOPlatformUUID line; plus the host name (information only). Output
# is read by target_store.parse_identity(). Plain sh syntax (bash/dash/zsh).
IDENTIFY_CMD = ('echo "machine-id=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null)"; '
                '[ -x /usr/sbin/ioreg ] && /usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID; '
                'echo "hostname=$(hostname 2>/dev/null)"')
# Host key check (HostKeyCheck): OpenSSH known_hosts files, read only (never
# written; a missing file is simply empty), plus hosts.json (target_store).
KNOWN_HOSTS_FILES = ('~/.ssh/known_hosts', '/etc/ssh/ssh_known_hosts')


class HostKeyRefused(paramiko.SSHException):
    """The server's host key is not the one recorded for it (warning printed)."""


def key_fingerprint(key):
    """OpenSSH-style SHA256 fingerprint of a paramiko key, as `ssh-keygen -lf`
    shows it (no '=' padding)."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return 'SHA256:' + base64.b64encode(digest).decode('ascii').rstrip('=')


def known_hosts_keys(name, files=KNOWN_HOSTS_FILES):
    """Keys recorded for name ('host', or '[host]:port' for a port other than
    22, as ssh writes them) in OpenSSH known_hosts files, read only:
    [(key type, fingerprint, 'FILE line N')]. Plain and hashed (|1|...)
    names, also in comma lists. Not used: wildcard patterns, @cert-authority
    and @revoked lines, key types paramiko can't read (e.g. ssh-dss)."""
    name, found = name.lower(), []
    for path in files:
        path = os.path.expanduser(path)
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith(('#', '@')):
                continue
            try:
                entry = paramiko.hostkeys.HostKeyEntry.from_line(line, n)
            except Exception:   # unreadable line: skipped, as paramiko does
                continue
            if entry is None or entry.key is None:
                continue
            for h in entry.hostnames:
                try:
                    hit = h.lower() == name or (h.startswith('|1|')
                                                and paramiko.HostKeys.hash_host(name, h) == h)
                except Exception:   # malformed hashed name
                    hit = False
                if hit:
                    found.append((entry.key.get_name(), key_fingerprint(entry.key), f"{path} line {n}"))
                    break
    return found


def compare_hostkey(key_type, fp, known):
    """Decide on a server key (type, fingerprint) given the recorded keys
    [(type or None, fingerprint, where)] for that host. Returns 'match' (a
    recorded key is this one), 'new' (nothing recorded), 'changed' (a key of
    this type, or of unrecorded type, is recorded but not this one) or
    'other-type' (only keys of other types are recorded)."""
    if not known:
        return 'new'
    if any(f == fp for _t, f, _w in known):
        return 'match'
    if any(t in (key_type, None) for t, _f, _w in known):
        return 'changed'
    return 'other-type'


def _host_key_algorithms(key_type):
    """Host key algorithms that present a key of key_type (RSA has three)."""
    return ('rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa') if key_type == 'ssh-rsa' else (key_type,)


class HostKeyCheck(paramiko.MissingHostKeyPolicy):
    """paramiko calls this during connect(): after the key exchange, before
    login. The client loads no host keys of its own, so it is always called.
    Raising here stops the connection (LogCollector._check_hostkey)."""
    def __init__(self, collector):
        self.collector = collector

    def missing_host_key(self, client, hostname, key):
        self.collector._check_hostkey(key)


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


class LogCollector:
    def __init__(self, host: Optional[str] = None, user: Optional[str] = None, 
                 port: int = 22, key_file: Optional[str] = None):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.ssh = None
        self.system = platform.system()
        self.mac_levels = 'errors'   # macOS: 'errors' = error+fault only, 'all' = keyword filter
        self.last_error = None       # set by get_logs() when collection failed
        self.noise_filters = []      # from main.py (noise.yaml); macOS: also excluded in log show
        self.noise_at_source = 0     # how many of them went into the log show predicate
        self.own_lines_dropped = 0   # macOS: lines from this process or its log show child
        self.connect_error = None    # first SSH connect/key error; later calls raise it again
        self.accept_hostkey_change = False   # main.py --accept-hostkey-change
        self.known_hosts_files = KNOWN_HOSTS_FILES
        self.hostkey_refused = False # True: changed host key, connection refused (warning printed)
        self.hostkey_info = None     # set by _check_hostkey: type, fingerprint, verdict
        self._recorded_keys = []     # [(type, fingerprint, where)] for this host, for _check_hostkey

    @staticmethod
    def _check_result(what, rc, stdout, stderr):
        """Raise with the command's own error text if it failed (non-zero exit,
        or no output but something on stderr); else print any stderr as a warning."""
        err = (stderr or '').strip()
        if rc != 0 or (err and not (stdout or '').strip()):
            raise RuntimeError(f"{what} failed (exit {rc}): {err or 'no error message'}")
        if err:
            print(f"Warning from {what}: {err}", file=sys.stderr)

    def _get_logs_macos(self, since: str) -> List[str]:
        """Get logs from local macOS system as LogLine objects (ndjson gives the
        real log level and full process names, which syslog style does not)."""
        # Convert our timestamp to macOS log show format
        since_dt = datetime.strptime(since, '%Y-%m-%d %H:%M:%S')
        macos_time = since_dt.strftime('%Y-%m-%d %H:%M:%S')
        predicate = MAC_KEYWORD_PREDICATE if self.mac_levels == 'all' else MAC_LEVEL_PREDICATE
        if self.noise_filters:   # known noise: AND NOT (...), so log show never returns it
            from noise_filters import mac_exclusions
            extra, self.noise_at_source = mac_exclusions(self.noise_filters)
            predicate += extra

        cmd = [
            'log', 'show',
            '--start', macos_time,
            '--style', 'ndjson',   # one JSON object per line (json = one big array)
            '--predicate', predicate
        ]

        # Popen instead of run(): the child's pid lets us drop its own log lines
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              encoding='utf-8', errors='replace') as proc:
            stdout, stderr = proc.communicate()
        self._check_result('log show', proc.returncode, stdout, stderr)
        stats = {}
        lines = parse_macos_ndjson(stdout, drop_pids={os.getpid(), proc.pid}, stats=stats)
        self.own_lines_dropped = stats.get('own', 0)
        return lines

    def _get_logs_linux(self, since: str) -> List[str]:
        """Get logs from local Linux system"""
        try:
            cmd = ['journalctl', '--since', since]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self._check_result('journalctl', result.returncode, result.stdout, result.stderr)
            return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get Linux logs: {str(e)}")

    def _get_logs_remote(self, seconds: int) -> List[str]:
        """Get logs from remote system via SSH (the last `seconds` seconds)"""
        self._connect_ssh()
        # Relative time, so the remote host's own clock/time zone decides the
        # window (an absolute Mac-local timestamp is read in the remote's zone).
        cmd = f"journalctl --since '{int(seconds)}s ago'"
        
        try:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            out = stdout.read().decode('utf-8', 'replace')
            err = stderr.read().decode('utf-8', 'replace')
            rc = stdout.channel.recv_exit_status()
        except Exception as e:
            raise RuntimeError(f"Failed to get remote logs: {str(e)}")
        self._check_result(f"journalctl on {self.host}", rc, out, err)
        return out.splitlines()

    def _connect_ssh(self):
        """Establish SSH connection if needed. A failure is kept and raised again
        on later calls (identify() connects first; get_logs() must not retry)."""
        if self.connect_error:
            raise RuntimeError(self.connect_error)
        if self.ssh is None and self.host and self.user:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(HostKeyCheck(self))   # _check_hostkey

            connect_kwargs = {
                'hostname': self.host,
                'username': self.user,
                'port': self.port
            }
            # Host keys recorded for this host (ssh's name for it: [host]:port
            # unless port 22): known_hosts first, then hosts.json by --host name.
            import target_store
            self._kh_name = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
            self._known_hosts_keys = known_hosts_keys(self._kh_name, self.known_hosts_files)
            registry_keys, self._registry_problem = target_store.recorded_hostkeys(self.host)
            self._recorded_keys = self._known_hosts_keys + registry_keys
            self._pinned = 'transport_factory' in inspect.signature(self.ssh.connect).parameters
            if self._pinned:   # paramiko 3.2+: ask for the recorded key types first
                connect_kwargs['transport_factory'] = self._transport

            if self.key_file:
                key_file = os.path.expanduser(self.key_file)  # Expand ~ in path
                try:
                    pkey = self._try_load_key(key_file)
                    connect_kwargs['pkey'] = pkey
                except Exception as e:
                    self.connect_error = f"Failed to load SSH key: {str(e)}"
                    raise RuntimeError(self.connect_error)
            
            try:
                self.ssh.connect(**connect_kwargs)
            except HostKeyRefused as e:   # before login: nothing was run
                self.hostkey_refused = True
                self.connect_error = f"Host key verification failed for {self.host}: {e}"
                self.ssh.close()
                raise RuntimeError(self.connect_error)
            except Exception as e:
                self.connect_error = f"Failed to connect to {self.host}: {str(e)}"
                raise RuntimeError(self.connect_error)

    def _transport(self, *args, **kwargs):
        """paramiko transport_factory: offer the host key types that have a
        recorded key for this host first (else paramiko's order), so a server
        that still has such a key presents that one and it can be compared."""
        t = paramiko.Transport(*args, **kwargs)
        algs = {a for kt, _f, _w in self._recorded_keys if kt for a in _host_key_algorithms(kt)}
        opts = t.get_security_options()
        opts.key_types = ([k for k in opts.key_types if k in algs]
                          + [k for k in opts.key_types if k not in algs])
        return t

    def _check_hostkey(self, key):
        """Called by HostKeyCheck during connect(), before login. Recorded key
        matches -> go on. Nothing recorded -> accept (like ssh's accept-new),
        stderr note; identify()/hosts.json record it. Changed (or only other
        key types recorded) -> ssh-style warning on stderr and HostKeyRefused,
        unless --accept-hostkey-change (then a note; hosts.json replaces the
        old key of that type)."""
        kt, fp = key.get_name(), key_fingerprint(key)
        name, known = self._kh_name, self._recorded_keys
        verdict = compare_hostkey(kt, fp, known)
        self.hostkey_info = {'type': kt, 'fingerprint': fp, 'verdict': verdict}
        old_kh = [w for t, f, w in self._known_hosts_keys if f != fp]

        def note(text):
            print(f"{name}: {text}", file=sys.stderr)
        if verdict == 'match':
            stale = [w for t, f, w in self._known_hosts_keys if t == kt and f != fp]
            if stale:
                note(f"host key OK, but known_hosts also has an older {kt} key for it "
                     f"({', '.join(stale)}). If the key changed on purpose: ssh-keygen -R '{name}', "
                     f"then ssh to it once")
            if self.accept_hostkey_change:
                note("--accept-hostkey-change: the host key is already known (hosts.json keeps "
                     f"only this {kt} key for it)")
            return
        if verdict == 'new':
            note(f"new host (not in known_hosts or hosts.json): {kt} key {fp} accepted, "
                 f"hosts.json records it" + (f" (hosts.json unreadable: {self._registry_problem})"
                                             if self._registry_problem else ''))
            return
        if verdict == 'other-type' and not self._pinned:   # old paramiko: can't ask for a type
            note(f"WARNING: {kt} key {fp} accepted UNCHECKED: only keys of other types are "
                 f"recorded for it and this paramiko can't ask for those")
            return
        if self.accept_hostkey_change:
            self.hostkey_info['verdict'] = 'accepted-change'
            note(f"host key CHANGE accepted (--accept-hostkey-change): now {kt} {fp}; hosts.json "
                 f"records it in place of its old {kt} key(s)")
            if old_kh:
                note(f"known_hosts still has the old key(s) ({', '.join(old_kh)}); ai_logs never "
                     f"edits it. Remove them with: ssh-keygen -R '{name}'")
            return
        self.hostkey_refused = True
        print(self._hostkey_warning(verdict, kt, fp), file=sys.stderr)
        raise HostKeyRefused(f"{kt} key {fp} is not the one recorded for it (warning above)")

    def _hostkey_warning(self, verdict, kt, fp):
        """The OpenSSH-style text for a refused host key (stderr)."""
        name = self._kh_name
        file_type = {'ssh-ed25519': 'ed25519', 'ssh-rsa': 'rsa', 'ssh-dss': 'dsa'}.get(
            kt, 'ecdsa' if kt.startswith('ecdsa') else kt)
        why = ("Either the server has new host keys (reinstalled, rebuilt, or restored from a\n"
               "backup without its old /etc/ssh keys), or someone is intercepting the\n"
               "connection (man-in-the-middle)." if verdict == 'changed' else
               f"It offered no key of a type recorded for it, only {kt}. Either that key type\n"
               "was removed on the server (or it was rebuilt), or someone is intercepting\n"
               "the connection (man-in-the-middle).")
        lines = ['@' * 62,
                 f"@  WARNING: HOST KEY FOR {name} "
                 f"{'HAS CHANGED' if verdict == 'changed' else 'IS OF ANOTHER TYPE'}!",
                 '@' * 62,
                 f"{name} now presents this host key:",
                 f"    {kt} {fp}",
                 "Recorded for it before:"]
        lines += [f"    {t or '(key type not recorded)'} {f}   ({w})" for t, f, w in self._recorded_keys]
        lines += [why,
                  "ai_logs did not log in, ran no command, collected nothing and wrote nothing.",
                  "Check on the server itself (its console, or over a network you trust):",
                  f"    ssh-keygen -lf /etc/ssh/ssh_host_{file_type}_key.pub",
                  "If that shows the new fingerprint above, run the same ai_logs command again",
                  "with --accept-hostkey-change (hosts.json then records the new key)."]
        if self._known_hosts_keys:
            lines.append(f"known_hosts has the old key too; ai_logs never edits it. After checking:\n"
                         f"    ssh-keygen -R '{name}'")
        return '\n'.join(lines)

    def _try_load_key(self, key_path: str, tries: int = 3) -> paramiko.PKey:
        """Try to load an SSH key (RSA, Ed25519, ECDSA; DSS only on old paramiko), prompting for passphrase if needed"""
        key_classes = [
            getattr(paramiko, name)
            for name in ('Ed25519Key', 'ECDSAKey', 'RSAKey', 'DSSKey')
            if hasattr(paramiko, name)   # DSSKey is gone in paramiko 4.0+
        ]

        last_error = None
        passphrase = None

        for attempt in range(tries):
            for key_class in key_classes:
                try:
                    if passphrase:
                        return key_class.from_private_key_file(key_path, password=passphrase)
                    else:
                        return key_class.from_private_key_file(key_path)
                except paramiko.ssh_exception.PasswordRequiredException:
                    # Key is passphrase-protected — ask once per attempt, then retry all types
                    if passphrase is None:
                        import getpass
                        passphrase = getpass.getpass(f'Enter passphrase for key {key_path}: ')
                    try:
                        return key_class.from_private_key_file(key_path, password=passphrase)
                    except paramiko.ssh_exception.SSHException:
                        if attempt < tries - 1:
                            print("Invalid passphrase. Please try again.")
                            passphrase = None  # Reset so we ask again
                        else:
                            raise RuntimeError("Failed to unlock private key after multiple attempts")
                except paramiko.ssh_exception.SSHException:
                    last_error = f"{key_class.__name__} format not recognized"
                    continue
                except Exception as e:
                    last_error = str(e)
                    continue

        raise RuntimeError(f"Could not load SSH key '{key_path}': {last_error}")

    def get_logs(self, hours: float = 1) -> List[str]:
        """Get logs from either local or remote system"""
        since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        self.last_error = None
        try:
            if self.host:
                return self._get_logs_remote(max(1, round(hours * 3600)))
            elif self.system == 'Darwin':
                return self._get_logs_macos(since)
            else:
                return self._get_logs_linux(since)
        except Exception as e:
            self.last_error = str(e)   # main.py: exit 1 instead of "No logs were collected"
            print(f"Error collecting logs: {str(e)}", file=sys.stderr)
            return []

    def identify(self) -> dict:
        """Which machine this is, for hosts.json (target_store.resolve_target):
        {'machine_id', 'hostkey', 'hostname', 'error'}. --host: connects (if not
        yet; get_logs() reuses the connection), takes the SHA256 fingerprint of
        the server's host key (OpenSSH style, as `ssh-keygen -lf` shows it) and
        runs IDENTIFY_CMD once. Local: target_store.local_identity(). Never
        raises; a failed connection is raised again by get_logs(). With a host
        key also 'hostkey_type' (e.g. ssh-ed25519) and 'hostkey_replace'
        (--accept-hostkey-change). A refused host key (self.hostkey_refused)
        is a failed connection: no command is run."""
        import target_store
        if not self.host:
            return target_store.local_identity()
        ident = {'machine_id': None, 'hostkey': None, 'hostname': None, 'error': None}
        try:
            self._connect_ssh()
            if self.ssh is None:   # no --user: nothing to connect with
                ident['error'] = 'no SSH connection'
                return ident
            key = self.ssh.get_transport().get_remote_server_key()
            ident['hostkey'] = key_fingerprint(key)
            ident['hostkey_type'] = key.get_name()
            ident['hostkey_replace'] = bool(self.accept_hostkey_change)
        except Exception as e:
            ident['error'] = 'no SSH connection' if self.connect_error else f"no SSH host key: {e}"
            if self.connect_error:
                return ident
        try:
            _stdin, stdout, _stderr = self.ssh.exec_command(IDENTIFY_CMD, timeout=20)
            out = stdout.read().decode('utf-8', 'replace')
            stdout.channel.recv_exit_status()
            ident.update(target_store.parse_identity(out))
        except Exception as e:
            ident['error'] = f"identity command failed: {e}"
        if not ident['machine_id'] and not ident['error']:
            ident['error'] = 'no machine-id in the reply'
        return ident

    def __del__(self):
        """Clean up SSH connection if it exists"""
        if self.ssh:
            try:
                self.ssh.close()
            except:
                pass
