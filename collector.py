# collector.py
# History:
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
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.host,
                'username': self.user,
                'port': self.port
            }
            
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
            except Exception as e:
                self.connect_error = f"Failed to connect to {self.host}: {str(e)}"
                raise RuntimeError(self.connect_error)

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
        raises; a failed connection is raised again by get_logs()."""
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
            digest = hashlib.sha256(key.asbytes()).digest()
            ident['hostkey'] = 'SHA256:' + base64.b64encode(digest).decode('ascii').rstrip('=')
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
