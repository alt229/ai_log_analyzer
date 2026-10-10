# docker_collector.py
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json
import sys

class RemoteDockerLogCollector:
    def __init__(self, ssh_client, config: dict):
        self.ssh = ssh_client
        self.max_lines = config.get('max_log_lines', 1000)
        self.excluded = config.get('excluded_containers', [])
        self.socket_path = config.get('socket', '/var/run/docker.sock')
        self.errors = []   # failed `docker logs` calls; main.py exits 1 if any

    def _run(self, command: str) -> tuple:
        """Execute command over SSH: (stdout, stderr, remote exit status)"""
        # Add DOCKER_HOST environment variable if custom socket is specified
        if self.socket_path:
            command = f'DOCKER_HOST="unix://{self.socket_path}" {command}'
        stdin, stdout, stderr = self.ssh.exec_command(command)
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace')
        return out, err, stdout.channel.recv_exit_status()

    def _exec_command(self, command: str) -> tuple:
        """Execute command over SSH and return output"""
        out, err, _ = self._run(command)
        return out, err

    def get_containers(self) -> List[Dict]:
        """Get list of running containers"""
        command = 'docker ps --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"'
        stdout, stderr, rc = self._run(command)

        if rc != 0:   # e.g. permission denied on the socket, docker not installed
            raise RuntimeError(f"docker ps failed (exit {rc}): {stderr.strip() or 'no error message'}")
        if stderr.strip():
            print(f"Warning getting containers: {stderr.strip()}", file=sys.stderr)
            
        containers = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            id_, name, image, status = line.split('\t')
            if name not in self.excluded:
                containers.append({
                    'id': id_,
                    'name': name,
                    'image': image,
                    'status': status
                })
        return containers

    def get_container_logs(self, hours: float = 1, container_name: Optional[str] = None) -> Dict[str, List[str]]:
        """Get logs from containers"""
        # Relative duration ("900s"): docker on the remote host counts back from
        # its own clock, so the Mac's time zone does not shift the window.
        since_arg = f"{max(1, round(hours * 3600))}s"
        logs = {}

        containers = self.get_containers()
        for container in containers:
            # Skip if not the requested container
            if container_name and container['name'] != container_name:
                continue

            command = f'docker logs --since {since_arg} --tail {self.max_lines} --timestamps {container["id"]}'
            stdout, stderr, rc = self._run(command)

            if rc != 0:
                msg = (f"docker logs {container['name']} failed (exit {rc}): "
                       f"{stderr.strip() or 'no error message'}")
                print(f"Error: {msg}", file=sys.stderr)
                self.errors.append(msg)
                continue

            # Exit 0: stderr is the container's own stderr stream, i.e. log lines
            # too. Both carry --timestamps (fixed width), so sorting merges them.
            lines = stdout.splitlines() + stderr.splitlines()
            if lines:
                logs[container['name']] = sorted(lines, key=lambda l: l.split(' ', 1)[0])

        return logs

    def get_container_stats(self, container_name: Optional[str] = None) -> Dict[str, Dict]:
        """Get current stats for containers"""
        stats = {}
        
        containers = self.get_containers()
        for container in containers:
            # Skip if not the requested container
            if container_name and container['name'] != container_name:
                continue

            # Get container stats
            command = f'docker stats {container["id"]} --no-stream --format "{{{{json .}}}}"'
            stdout, stderr = self._exec_command(command)
            
            if stderr:
                print(f"Warning getting stats for {container['name']}: {stderr}")
                continue
                
            if stdout:
                try:
                    container_stats = json.loads(stdout)
                    stats[container['name']] = {
                        'status': container['status'],
                        'image': container['image'],
                        'stats': container_stats
                    }
                except json.JSONDecodeError:
                    print(f"Error parsing stats for {container['name']}")

        return stats