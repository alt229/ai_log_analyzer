# docker_collector.py
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json

class RemoteDockerLogCollector:
    def __init__(self, ssh_client, config: dict):
        self.ssh = ssh_client
        self.max_lines = config.get('max_log_lines', 1000)
        self.excluded = config.get('excluded_containers', [])
        self.socket_path = config.get('socket', '/var/run/docker.sock')

    def _exec_command(self, command: str) -> tuple:
        """Execute command over SSH and return output"""
        # Add DOCKER_HOST environment variable if custom socket is specified
        if self.socket_path:
            command = f'DOCKER_HOST="unix://{self.socket_path}" {command}'
        stdin, stdout, stderr = self.ssh.exec_command(command)
        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')

    def get_containers(self) -> List[Dict]:
        """Get list of running containers"""
        command = 'docker ps --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"'
        stdout, stderr = self._exec_command(command)
        
        if stderr:
            print(f"Warning getting containers: {stderr}")
            return []
            
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
        since = datetime.now() - timedelta(hours=hours)
        since_arg = since.strftime('%Y-%m-%dT%H:%M:%S')
        logs = {}

        containers = self.get_containers()
        for container in containers:
            # Skip if not the requested container
            if container_name and container['name'] != container_name:
                continue

            command = f'docker logs --since {since_arg} --tail {self.max_lines} --timestamps {container["id"]}'
            stdout, stderr = self._exec_command(command)
            
            if stderr:
                print(f"Warning getting logs for {container['name']}: {stderr}")
                continue
                
            if stdout:
                logs[container['name']] = stdout.splitlines()

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