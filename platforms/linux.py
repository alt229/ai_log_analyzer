#=============================================================================
# platforms/linux.py - Linux with the systemd journal (journalctl)
#=============================================================================
#
# WHAT IT DOES
# The journal for a time window in journalctl's default text format
# ("Oct 10 18:14:36 host proc[pid]: message"), one str per line.
# Local: `journalctl --since <local time>`. Remote (SSH, and --guest via
# pct exec): `journalctl --since 'Ns ago'`, so the remote clock and time
# zone decide the window. Severity is guessed later from keywords
# (analyzer.py); the journal's own PRIORITY is not used (yet).
#
# Moved here from collector.py unchanged; written 2026-10-10 by Script
# Wrangler (Claude) for ai_logs (platforms.patch).
# History:
# 2026-10-10 - Script Wrangler: first version (moved from collector.py).
#=============================================================================
import subprocess

NAME = 'linux'
TOOL = 'journalctl'


def local_logs(collector, since):
    """Local Linux journal since `since` ('%Y-%m-%d %H:%M:%S')."""
    try:
        cmd = ['journalctl', '--since', since]
        result = subprocess.run(cmd, capture_output=True, text=True)
        collector._check_result('journalctl', result.returncode, result.stdout, result.stderr)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to get Linux logs: {str(e)}")


def remote_cmd(collector, seconds):
    """Shell command for the last `seconds` seconds (relative, so the remote
    host's own clock/time zone decides the window; an absolute Mac-local
    timestamp would be read in the remote's zone)."""
    return f"journalctl --since '{int(seconds)}s ago'"


def parse(collector, text):
    return text.splitlines()
