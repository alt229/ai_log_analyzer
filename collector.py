# collector.py
import subprocess
from datetime import datetime, timedelta
import paramiko
from typing import List, Optional
import platform
import os

class LogCollector:
    def __init__(self, host: Optional[str] = None, user: Optional[str] = None, 
                 port: int = 22, key_file: Optional[str] = None):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.ssh = None
        self.system = platform.system()

    def _get_logs_macos(self, since: str) -> List[str]:
        """Get logs from local macOS system"""
        try:
            # Convert our timestamp to macOS log show format
            since_dt = datetime.strptime(since, '%Y-%m-%d %H:%M:%S')
            macos_time = since_dt.strftime('%Y-%m-%d %H:%M:%S')
            
            cmd = [
                'log', 'show',
                '--start', macos_time,
                '--style', 'syslog',  # Make it look more like Linux logs
                '--predicate', '(eventMessage CONTAINS[c] "error" OR eventMessage CONTAINS[c] "warning" OR eventMessage CONTAINS[c] "failure" OR eventMessage CONTAINS[c] "failed" OR process == "system")'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get macOS logs: {str(e)}")

    def _get_logs_linux(self, since: str) -> List[str]:
        """Get logs from local Linux system"""
        try:
            cmd = ['journalctl', '--since', since]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get Linux logs: {str(e)}")

    def _get_logs_remote(self, since: str) -> List[str]:
        """Get logs from remote system via SSH"""
        self._connect_ssh()
        cmd = f"journalctl --since '{since}'"
        
        try:
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            return stdout.read().decode().splitlines()
        except Exception as e:
            raise RuntimeError(f"Failed to get remote logs: {str(e)}")
        finally:
            if stderr:
                err = stderr.read().decode().strip()
                if err:
                    print(f"Warning: {err}")

    def _connect_ssh(self):
        """Establish SSH connection if needed"""
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
                    raise RuntimeError(f"Failed to load SSH key: {str(e)}")
            
            try:
                self.ssh.connect(**connect_kwargs)
            except Exception as e:
                raise RuntimeError(f"Failed to connect to {self.host}: {str(e)}")

    def _try_load_key(self, key_path: str, tries: int = 3) -> paramiko.PKey:
        """Try to load an SSH key, prompting for passphrase if needed"""
        for attempt in range(tries):
            try:
                return paramiko.RSAKey.from_private_key_file(key_path)
            except paramiko.ssh_exception.PasswordRequiredException:
                try:
                    import getpass
                    passphrase = getpass.getpass(f'Enter passphrase for key {key_path}: ')
                    return paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)
                except paramiko.ssh_exception.SSHException as e:
                    if attempt < tries - 1:
                        print("Invalid passphrase. Please try again.")
                    else:
                        raise RuntimeError("Failed to unlock private key after multiple attempts")
            except Exception as e:
                raise RuntimeError(f"Error loading SSH key: {str(e)}")

    def get_logs(self, hours: float = 1) -> List[str]:
        """Get logs from either local or remote system"""
        since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            if self.host:
                return self._get_logs_remote(since)
            elif self.system == 'Darwin':
                return self._get_logs_macos(since)
            else:
                return self._get_logs_linux(since)
        except Exception as e:
            print(f"Error collecting logs: {str(e)}")
            return []

    def __del__(self):
        """Clean up SSH connection if it exists"""
        if self.ssh:
            try:
                self.ssh.close()
            except:
                pass
