#!/usr/bin/env python3
#=============================================================================
# target_store.py - Per-machine data folder for ai_logs (noise.yaml, baselines)
#=============================================================================
#
# WHAT IT DOES
# Works out which folder belongs to the machine being ANALYZED and writes
# files there safely. The folder is ~/.local/share/ai_logs/<target>/,
# where <target> is the local short host name for --local (macOS:
# LocalHostName in the network prefs plist, else socket.gethostname();
# lower-case, domain suffix removed) or the --host name as typed (a
# trailing ".local" removed, made filename-safe). It holds noise.yaml and
# baseline.json / baseline-docker.json.
# hosts.json in the same root remembers which folder is which MACHINE
# (Linux machine-id / macOS IOPlatformUUID, SSH host key fingerprints,
# every name or IP used for it), so one machine reached by another name or
# IP reuses its folder instead of getting a new one (resolve_target).
#
# USAGE
# Library module for main.py, noise_filters.py and baseline.py:
#   t = local_target()  or  host_target('andromeda.local')   -> 'andromeda'
#   d = target_dir(t)                     ~/.local/share/ai_logs/andromeda
#   atomic_write(os.path.join(d, 'noise.yaml'), text)
#   folder, notes = resolve_target(name_typed, t, ident)   (notes: stderr)
#       ident = collector.identify() (dict); None = name lookup only
#   text, status = list_targets()        ok, msg = rename_target(old, new)
#
# REQUIRES
# Python 3.7+ standard library. macOS: reads (never writes)
# /Library/Preferences/SystemConfiguration/preferences.plist for --local.
# local_identity() runs /usr/sbin/ioreg on macOS, else reads
# /etc/machine-id (or /var/lib/dbus/machine-id).
#
# SIDE EFFECTS
# local_target() reads the plist above on macOS. atomic_write()
# creates the folder (mode 700) and writes a temp file that is renamed over
# the target (mode 600). Nothing is ever deleted: if a write fails, the
# temp file stays and its name is in the error.
# resolve_target() rewrites hosts.json (same way) when something changed:
# new machine or name, new host key, a new last_seen day. An unreadable
# hosts.json is first copied to hosts.json.bad-YYYYmmdd-HHMMSS (a new
# file, never overwritten) and a stderr line says so. rename_target()
# renames one folder (os.rename) and its entry; never if NEW exists.
#
# CAVEATS
# - One machine, one folder: --local on andromeda, --host andromeda.local
#   and --host 10.0.0.7 share andromeda/ once hosts.json has seen the same
#   machine-id (else SSH host key). Without an identity (no connection, no
#   id) the folder is picked by name as before (a known alias still finds
#   its folder). Names: only ".local" is removed (andromeda.lan stays).
# - Folder name = the first name used for the machine; --rename-target.
#   Folders from before hosts.json are adopted by name, never moved.
# - A known name/IP that now answers with a DIFFERENT machine-id (or host
#   key) - IP reused, or a reinstall - gets a NEW folder (NAME, else
#   NAME-2 ...) and a WARNING line. Copy noise.yaml over by hand if it is
#   the same server reinstalled.
# - VM clones that kept the same /etc/machine-id look like ONE machine
#   (each new host key gets a note). Give clones a new machine-id.
# - Renaming the Mac changes LocalHostName; hosts.json still finds the
#   old folder by machine-id and adds the new name as an alias.
# - hosts.json holds machine-ids (unique per machine): private, mode 600.
#
#-----------------------------------------------------------------------------
# Written 2026-10-09 by Script Wrangler (Claude) for ai_logs
# (noise-baseline.patch). Unit-tested with mocks only; UNTESTED for real.
# History:
# 2026-10-09 - Script Wrangler: hosts.json maps each machine (machine-id /
#   SSH host key) to one folder: resolve_target, list_targets,
#   rename_target, local_identity, parse_identity (hostid.patch).
#=============================================================================
import json
import os
import platform
import re
import plistlib
import socket
import subprocess
import tempfile
import time

DATA_ROOT = '~/.local/share/ai_logs'
# Where macOS keeps LocalHostName (System Settings > General > Sharing).
MAC_PREFS = '/Library/Preferences/SystemConfiguration/preferences.plist'


def data_root():
    return os.path.expanduser(DATA_ROOT)


def safe_name(text, limit=100):
    """Lower-case, only a-z 0-9 . _ - (others become _), no leading dots."""
    s = re.sub(r'[^a-z0-9._-]+', '_', str(text or '').strip().lower())
    return s.lstrip('.')[:limit]


def mac_local_hostname(path=MAC_PREFS):
    """LocalHostName from the macOS network prefs (stable: set in System
    Settings > Sharing, never has a domain). '' if missing or unreadable.
    Read directly from the prefs file; no command is run."""
    try:
        with open(path, 'rb') as f:
            prefs = plistlib.load(f)
        name = prefs.get('System', {}).get('Network', {}).get('HostNames', {}).get('LocalHostName', '')
        return name.strip() if isinstance(name, str) else ''
    except (OSError, ValueError, AttributeError, plistlib.InvalidFileException):
        return ''


def local_target(system=None, read_mac_name=None, gethostname=None):
    """Folder name for --local: this machine's short host name."""
    system = system or platform.system()
    read_mac_name = read_mac_name or mac_local_hostname
    gethostname = gethostname or socket.gethostname
    name = read_mac_name() if system == 'Darwin' else ''
    if not name:
        try:
            name = gethostname() or ''
        except OSError:
            name = ''
    return safe_name(name.strip().split('.')[0]) or 'localhost'


def host_target(host):
    """Folder name for --host H: H as typed, lower-case, '.local' removed."""
    h = str(host or '').strip().lower().rstrip('.')
    if h.endswith('.local'):
        h = h[:-len('.local')]
    return safe_name(h) or 'unknown-host'


def target_dir(target):
    return os.path.join(data_root(), target)


def ensure_dir(d):
    """Create folder d (mode 700). Inside the data root, the root and d are
    always set to 700; elsewhere (--noise-file) only a folder created here."""
    d = os.path.abspath(d)
    root = os.path.abspath(data_root())
    created = not os.path.isdir(d)
    os.makedirs(d, mode=0o700, exist_ok=True)
    inside = d == root or d.startswith(root + os.sep)
    for p in ([root, d] if inside else ([d] if created else [])):
        os.chmod(p, 0o700)


def atomic_write(path, text):
    """Write text to path: temp file in the same folder, mode 600, then
    os.replace. Never deletes anything; on failure the temp file is left."""
    folder = os.path.dirname(os.path.abspath(path))
    ensure_dir(folder)
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.',
                               suffix='.tmp', dir=folder)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception as e:
        raise OSError(f"could not write {path}: {e} (temp file {tmp} was left "
                      f"there; nothing was deleted)") from e


# --- Which folder is which machine: hosts.json ------------------------------
REGISTRY = 'hosts.json'
REGISTRY_NOTE = ('ai_logs: which folder in this directory belongs to which machine '
                 '(target_store.py). Keys of "machines" are folder names. Read it with '
                 '--list-targets; rename a folder with --rename-target OLD NEW.')
# Linux /etc/machine-id: 32 hex digits ("uninitialized", empty or all zeros = none)
_LINUX_MID = re.compile(r'[0-9a-f]{32}')
# macOS `ioreg -rd1 -c IOPlatformExpertDevice`:   "IOPlatformUUID" = "XXXXXXXX-XXXX-..."
_MAC_UUID = re.compile(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{32,36})"')


def parse_identity(text):
    """Output of collector.IDENTIFY_CMD (lines "machine-id=...", the ioreg
    IOPlatformUUID line, "hostname=...") -> {'machine_id', 'hostname'}, each
    a str or None. machine_id is lower-case."""
    mid = host = None
    for line in str(text or '').splitlines():
        line = line.strip()
        m = _MAC_UUID.search(line)
        if m:
            mid = mid or m.group(1).lower()
        elif line.startswith('machine-id='):
            v = line[len('machine-id='):].strip().lower()
            if _LINUX_MID.fullmatch(v) and v.strip('0'):
                mid = mid or v
        elif line.startswith('hostname='):
            host = line[len('hostname='):].strip() or None
    return {'machine_id': mid, 'hostname': host}


def local_identity(system=None, run=None, files=('/etc/machine-id', '/var/lib/dbus/machine-id')):
    """--local: this machine's identity, read here (no network). macOS: the
    IOPlatformUUID from /usr/sbin/ioreg; else the machine-id file. Same dict
    as collector.identify(); hostkey is None (no SSH involved)."""
    system = system or platform.system()
    run = run or subprocess.run
    lines, error = [], None
    if system == 'Darwin':
        try:
            r = run(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
                    capture_output=True, text=True, timeout=10)
            lines.append(r.stdout or '')
        except (OSError, subprocess.SubprocessError) as e:
            error = f"ioreg failed: {e}"
    else:
        for p in files:
            try:
                with open(p, encoding='utf-8') as f:
                    lines.append('machine-id=' + f.read().strip())
                break
            except OSError:
                continue
    try:
        lines.append('hostname=' + socket.gethostname())
    except OSError:
        pass
    ident = dict(parse_identity('\n'.join(lines)), hostkey=None, error=error)
    if not ident['machine_id'] and not error:
        ident['error'] = 'no machine-id found on this machine'
    return ident


def registry_path():
    return os.path.join(data_root(), REGISTRY)


def alias_key(name):
    """A typed name or IP as hosts.json stores it: lower-case, no trailing dot."""
    return str(name or '').strip().lower().rstrip('.')


def _empty_registry():
    return {'format': 1, 'note': REGISTRY_NOTE, 'machines': {}}


def _load(path):
    """hosts.json -> (registry, problem). A missing file is an empty registry.
    Unreadable or the wrong shape: an empty registry and a problem string
    (the file itself is not touched here)."""
    try:
        with open(path, encoding='utf-8') as f:
            reg = json.load(f)
    except FileNotFoundError:
        return _empty_registry(), None
    except (OSError, ValueError) as e:
        return _empty_registry(), f"{type(e).__name__}: {e}"
    machines = reg.get('machines') if isinstance(reg, dict) else None
    if not isinstance(machines, dict) or not all(isinstance(e, dict) for e in machines.values()):
        return _empty_registry(), 'not an ai_logs hosts.json (no "machines" object of entries)'
    return reg, None


def _backup(path):
    """Copy an unreadable hosts.json to hosts.json.bad-YYYYmmdd-HHMMSS (-2, -3
    ... if taken; a new file, never overwrites). Returns the copy's path."""
    with open(path, 'rb') as f:
        data = f.read()
    stamp = time.strftime('%Y%m%d-%H%M%S')
    for n in range(1, 100):
        dest = f"{path}.bad-{stamp}" + (f"-{n}" if n > 1 else '')
        try:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        return dest
    raise OSError('no free backup name')


def _update(change, path=None):
    """Read hosts.json, run change(registry) -> result, write the registry back
    if it changed. Reading right before writing keeps what a parallel run
    wrote meanwhile. Problems never raise: they become notes.
    Returns (result, notes, ok); ok is False if a needed write failed."""
    path = path or registry_path()
    reg, problem = _load(path)
    before = json.dumps(reg, sort_keys=True)
    result = change(reg)
    if json.dumps(reg, sort_keys=True) == before:
        return result, [], True
    notes = []
    if problem:
        try:
            bak = _backup(path)
        except OSError as e:
            return result, [f"{path} is unreadable ({problem}) and could not be backed up "
                            f"({e}): not updated"], False
        notes.append(f"{path} was unreadable ({problem}): copied to {bak}; a new one is "
                     f"started (folders are re-adopted by name as they are used)")
    try:
        atomic_write(path, json.dumps(reg, indent=1, ensure_ascii=False) + '\n')
    except OSError as e:
        return result, notes + [f"hosts.json not updated: {e}"], False
    return result, notes, True


def _aliases(e):
    a = e.get('aliases')
    return a if isinstance(a, dict) else {}


def _hostkeys(e):
    k = e.get('hostkeys')
    return [x for x in k if isinstance(x, str)] if isinstance(k, list) else []


def _has_id(e):
    return bool(e.get('machine_id') or _hostkeys(e))


def _log(e, today, text):
    """One dated line in the entry's history (the last 20 are kept)."""
    h = e.get('history') if isinstance(e.get('history'), list) else []
    e['history'] = (h + [f"{today} {text}"])[-20:]


def _seen(e, alias, today):
    al = _aliases(e)
    old = al.get(alias) if isinstance(al.get(alias), dict) else {}
    al[alias] = {'first_seen': old.get('first_seen') or today, 'last_seen': today}
    e['aliases'] = al
    e['last_seen'] = today


def _free_folder(base, machines):
    """base, else base-2, base-3 ...: the first name that is neither a folder
    in hosts.json nor anything that exists on disk."""
    for n in range(1, 1000):
        cand = base if n == 1 else f"{base}-{n}"
        if cand not in machines and cand != REGISTRY and not os.path.lexists(target_dir(cand)):
            return cand
    return f"{base}-{time.strftime('%Y%m%d-%H%M%S')}"


def _short(text, n=12):
    return (text[:n] + '...') if text and len(text) > n else (text or '-')


def _match(reg, alias, name, default, mid, hk, hostname, today):
    """The decision behind resolve_target(), done on a freshly read registry
    (changed in place). Returns (folder, notes)."""
    machines = reg['machines']
    by_alias = next((f for f, e in machines.items() if alias in _aliases(e)), None)
    folder = how = None
    if mid:
        folder = next((f for f, e in machines.items() if e.get('machine_id') == mid), None)
        how = 'same machine-id'
    if folder is None and hk:   # an entry with another machine-id is another machine
        folder = next((f for f, e in machines.items()
                       if hk in _hostkeys(e) and not (mid and e.get('machine_id'))), None)
        how = 'same SSH host key'
    if folder is None:          # an entry made without any id (e.g. --rename-target): adopt it
        f = by_alias or default
        folder = f if f in machines and not _has_id(machines[f]) else None
        how = 'known name, no id recorded yet'
    parts = []
    if folder is not None:
        e = machines[folder]
        if folder != by_alias:  # a name not seen for this machine before
            if by_alias:
                machines[by_alias]['aliases'] = {a: v for a, v in _aliases(machines[by_alias]).items()
                                                 if a != alias}
                _log(machines[by_alias], today, f"name {alias} moved to {folder} ({how})")
            if (folder != default and default not in machines and os.path.isdir(target_dir(default))
                    and not os.path.lexists(target_dir(folder))):
                # its folder was never created, but this name has one from before: adopt that
                machines[default] = machines.pop(folder)
                _log(machines[default], today, f"folder {folder} (never created) renamed to "
                                              f"existing folder {default}")
                parts.append(f"{name} = {folder} ({how}): using the existing folder {default} "
                             f"for it (entry renamed)")
                folder, e = default, machines[default]
            elif folder != default:
                parts.append(f"{name} = {folder} ({how}): using its folder")
                if default not in machines and os.path.isdir(target_dir(default)):
                    parts.append(f"folder {default}/ from before is not used for it any more "
                                 f"(merge or remove it by hand)")
            if by_alias and by_alias != folder:
                parts.append(f"{name} belonged to {by_alias} before")
            _log(e, today, f"name {alias} added ({how})")
        if hk and hk not in _hostkeys(e):
            if _hostkeys(e):
                parts.append(f"{folder}: new SSH host key {_short(hk, 19)} recorded ({how})")
                _log(e, today, f"new SSH host key {hk} ({how})")
            e['hostkeys'] = _hostkeys(e) + [hk]
        if mid and not e.get('machine_id'):
            e['machine_id'] = mid
    else:
        if by_alias:            # known name, but another machine answers now
            folder = _free_folder(default, machines)
            old = machines[by_alias]
            what = 'machine-id' if (mid and old.get('machine_id')) else 'SSH host key'
            parts.append(f"WARNING: {name} is not the machine seen there before (other {what} "
                         f"than folder {by_alias}; IP reused or reinstalled?): using new folder {folder}")
            old['aliases'] = {a: v for a, v in _aliases(old).items() if a != alias}
            _log(old, today, f"name {alias} now answers as another machine: moved to {folder}")
        elif default in machines or default == REGISTRY or (
                os.path.lexists(target_dir(default)) and not os.path.isdir(target_dir(default))):
            folder = _free_folder(default, machines)
            parts.append(f"{name}: folder {default} belongs to another machine; using new folder {folder}")
        else:
            folder = default
            adopted = os.path.isdir(target_dir(folder))
            parts.append(f"{name}: new in hosts.json, folder {folder}"
                         + (' (existing folder adopted)' if adopted else ''))
        e = machines[folder] = {'machine_id': mid, 'hostkeys': [hk] if hk else [],
                                'hostname': hostname, 'aliases': {}, 'first_seen': today}
        _log(e, today, f"registered as {alias}" + (f" ({parts[0]})" if parts[0].startswith('WARNING')
                                                   else ''))
    if hostname:
        e['hostname'] = hostname
    _seen(e, alias, today)
    return folder, ['; '.join(parts)] if parts else []


def resolve_target(name, default, ident=None, path=None, today=None):
    """Folder for the machine reached as `name` (--host as typed; --local: the
    local name). default = the folder name used before hosts.json
    (host_target(name) or local_target()). ident = collector.identify():
    {'machine_id', 'hostkey', 'hostname', 'error'}; None = not looked up
    (--baseline-info: no connection), then only the name is looked up and
    nothing is written. Returns (folder, notes); notes are stderr lines."""
    path = path or registry_path()
    alias = alias_key(name) or default
    mid = (ident or {}).get('machine_id') or None
    hk = (ident or {}).get('hostkey') or None
    if not (mid or hk):
        reg, problem = _load(path)
        folder = next((f for f, e in reg['machines'].items() if alias in _aliases(e)), None) or default
        notes = [f"{path} is unreadable ({problem}): ignored for this run"] if problem else []
        if ident is not None:
            notes.append(f"{name}: machine not identified ({ident.get('error') or 'no machine-id or host key'}); "
                         f"folder {folder} chosen by name, as before")
        return folder, notes
    (folder, notes), more, _ok = _update(
        lambda reg: _match(reg, alias, name, default, mid, hk, (ident or {}).get('hostname'),
                           today or time.strftime('%Y-%m-%d')), path)
    return folder, more + notes   # hosts.json problems first


def rename_target(old, new, path=None, today=None):
    """--rename-target OLD NEW: rename folder OLD (a folder name, or any name /
    IP recorded for it) to NEW, in the data root and in hosts.json. OLD stays
    as an alias. No connection needed. Refuses if NEW exists (folder, file or
    entry) or OLD is unknown. Returns (ok, message)."""
    path = path or registry_path()
    today = today or time.strftime('%Y-%m-%d')
    reg, problem = _load(path)
    if problem:
        return False, f"{path} is unreadable ({problem}); fix or move it first. Nothing renamed."
    machines = reg['machines']
    key = alias_key(old)
    src = next((f for f in (key, safe_name(key), host_target(key)) if f in machines), None)
    src = src or next((f for f, e in machines.items() if key in _aliases(e)), None)
    src = src or next((f for f in (safe_name(key), host_target(key))
                       if f and f != REGISTRY and os.path.isdir(target_dir(f))), None)
    dst = safe_name(alias_key(new))
    if not src:
        return False, f"--rename-target: no folder or known name '{old}' (see --list-targets). Nothing renamed."
    if not dst or dst == REGISTRY or dst.startswith(REGISTRY + '.'):
        return False, f"--rename-target: '{new}' can't be a folder name. Nothing renamed."
    if dst == src:
        return False, f"--rename-target: {src} already has that name. Nothing renamed."
    if dst in machines or os.path.lexists(target_dir(dst)):
        return False, f"--rename-target: {target_dir(dst)} already exists. Nothing renamed."
    moved = os.path.isdir(target_dir(src))
    if moved:
        try:
            os.rename(target_dir(src), target_dir(dst))
        except OSError as e:
            return False, f"--rename-target: {e}. Nothing renamed."

    def change(reg):
        m = reg['machines']
        e = m.pop(src, None) or {'machine_id': None, 'hostkeys': [], 'hostname': None,
                                 'aliases': {}, 'first_seen': today}
        e['aliases'] = _aliases(e)
        e['aliases'].setdefault(key, {'first_seen': today, 'last_seen': today})
        _log(e, today, f"renamed from {src}")
        m[dst] = e

    _, notes, ok = _update(change, path)
    if not ok:
        if moved:
            try:
                os.rename(target_dir(dst), target_dir(src))
            except OSError as e:
                return False, ' '.join(notes) + (f" The folder is now {target_dir(dst)} and could "
                                                 f"not be renamed back ({e}).")
        return False, ' '.join(notes) + f" Folder {src} left as it was."
    return True, (f"Renamed {target_dir(src)} -> {target_dir(dst)}" if moved else
                  f"Renamed {src} -> {dst} in hosts.json (it has no folder yet)") + \
        f"; '{key}' stays a name for it." + (' ' + ' '.join(notes) if notes else '')


def list_targets(path=None):
    """--list-targets: hosts.json as text (folders, names/IPs with last day
    seen, short machine-id and host keys), plus folders not in it yet.
    Returns (text, status): 1 if hosts.json is unreadable, else 0."""
    path = path or registry_path()
    reg, problem = _load(path)
    if problem:
        return f"{path} is unreadable: {problem}", 1
    machines = reg['machines']
    out = [f"{path}: {len(machines)} machine(s)" if os.path.exists(path) else
           f"{path}: not created yet (written by the next --host or --local run)"]
    for folder in sorted(machines):
        e = machines[folder]
        names = sorted(_aliases(e).items(), key=lambda kv: str((kv[1] or {}).get('first_seen', ''))
                       if isinstance(kv[1], dict) else '')
        out.append(f"\n{folder}" + ('' if os.path.isdir(target_dir(folder)) else '   (no folder yet)'))
        out.append('  names:      ' + (', '.join(
            f"{a} (last {v.get('last_seen', '?') if isinstance(v, dict) else '?'})" for a, v in names) or '-'))
        out.append(f"  machine-id: {_short(e.get('machine_id'))}   host key(s): "
                   f"{', '.join(_short(k, 19) for k in _hostkeys(e)) or '-'}   "
                   f"hostname: {e.get('hostname') or '-'}")
        out.append(f"  first seen {e.get('first_seen', '?')}, last seen {e.get('last_seen', '?')}")
    try:
        extra = sorted(d for d in os.listdir(data_root())
                       if d not in machines and os.path.isdir(target_dir(d)))
    except OSError:
        extra = []
    if extra:
        out.append('\nFolders not in hosts.json yet (adopted the first time that name is used): '
                   + ', '.join(extra))
    return '\n'.join(out), 0
