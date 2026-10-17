#=============================================================================
# platforms/__init__.py - Which OS a target runs, and its log commands
#=============================================================================
#
# WHAT IT DOES
# ai_logs separates HOW a machine is reached (collector.py: local
# subprocess, SSH, SSH + `pct exec` for --guest) from WHAT is run there and
# how the output is read (one module per OS in this package). Each platform
# module has the same small interface (see Platform below): the command
# for a time window, the parser for its output, and its name. This file
# holds the registry and the detection.
#
# DETECTION (remote)
# 1. The SSH server banner, which the connection already received (no
#    command): RouterOS says "ROSSSH" -> not a Unix shell, no probe is run
#    (no RouterOS module yet: a clear error).
# 2. Else one probe command, PROBE_CMD, wrapped in `sh -c '...'` so it also
#    works when the login shell is csh/tcsh (FreeBSD root). It prints the OS
#    name (uname -s), whether journalctl exists, pfSense's /etc/platform,
#    and the identity lines target_store.parse_identity() reads (machine-id,
#    macOS IOPlatformUUID, hostname). So detection and identification are
#    ONE remote command, as identification alone was before.
# Local: platform.system() (Darwin / Linux). --platform NAME skips
# detection.
#
# USAGE
#   from platforms import detect, get, PROBE_CMD
#   name, why = detect(banner, probe_output)   # 'linux', 'darwin', ... or None
#   p = get(name)                               # module with the interface
#
# Written 2026-10-10 by Script Wrangler (Claude) for ai_logs
# (platforms.patch: refactor, no change for Linux and local macOS).
# History:
# 2026-10-10 - Script Wrangler: first version (linux, darwin).
#=============================================================================
import re

from . import darwin, linux

# name -> module. Order matters only for listing.
PLATFORMS = {'linux': linux, 'darwin': darwin}

# Detection + identity in one command (see header). Plain POSIX sh inside
# single quotes, so a csh/tcsh login shell passes it through unchanged.
# No single quotes may appear inside.
_PROBE_SH = ('echo "os=$(uname -s 2>/dev/null)"; '
             'echo "journalctl=$(command -v journalctl 2>/dev/null)"; '
             '[ -r /etc/platform ] && echo "platform=$(head -n1 /etc/platform)"; '
             'echo "machine-id=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null)"; '
             '[ -x /usr/sbin/ioreg ] && /usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID; '
             'echo "hostname=$(hostname 2>/dev/null)"')
PROBE_CMD = f"sh -c '{_PROBE_SH}'"


def names():
    return list(PLATFORMS)


def get(name):
    """The platform module for name (KeyError if unknown)."""
    return PLATFORMS[name]


def probe_fields(text):
    """PROBE_CMD output -> {'os', 'journalctl', 'platform'} (str, '' if absent)."""
    out = {'os': '', 'journalctl': '', 'platform': ''}
    for line in str(text or '').splitlines():
        k, sep, v = line.strip().partition('=')
        if sep and k in out:
            out[k] = v.strip()
    return out


def detect(banner=None, probe=None):
    """(name or None, why). banner = the SSH server's version string (e.g.
    'SSH-2.0-OpenSSH_10.0p2 Debian-7'); probe = PROBE_CMD output (None = not
    run). None + why when no supported platform fits."""
    b = str(banner or '')
    if 'ROSSSH' in b:
        return None, 'MikroTik RouterOS (SSH banner ROSSSH): not supported yet'
    f = probe_fields(probe)
    os_name = f['os']
    if os_name == 'Linux':
        if f['journalctl']:
            return 'linux', 'uname Linux, journalctl found'
        return None, ('Linux without journalctl (no systemd journal, e.g. Alpine): '
                      'not supported yet')
    if os_name == 'Darwin':
        return 'darwin', 'uname Darwin'
    if os_name == 'FreeBSD':
        what = 'pfSense' if re.search(r'pfsense', f['platform'], re.I) else 'FreeBSD'
        return None, f"{what} (uname FreeBSD): not supported yet"
    if os_name:
        return None, f"uname {os_name}: not supported yet"
    hint = f" (SSH banner: {b})" if b else ''
    return None, f"OS not recognised: the probe printed no uname{hint}"
