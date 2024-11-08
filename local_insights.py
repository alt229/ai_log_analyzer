# local_insights.py
from collections import defaultdict
from datetime import datetime
import re
from typing import Dict, List
from colorama import Fore, Style

class LocalInsights:
    def __init__(self):
        self.backup_patterns = {
            'start': r'INFO: starting new backup job:.*',
            'vm_start': r'INFO: Starting Backup of VM (\d+)',
            'vm_finish': r'INFO: Finished Backup of VM (\d+) \(([^)]+)\)',
            'success': r'INFO: Backup job finished successfully',
            'failure': r'failed|error|warning'
        }
        
        self.service_patterns = {
            'start': r'Starting .* service',
            'stop': r'Stopping .* service',
            'failed': r'Failed to start .* service'
        }
    
    def analyze_backups(self, messages: List[str]) -> Dict:
        """Analyze backup job information"""
        backups = defaultdict(dict)
        current_job = None
        
        for msg in messages:
            if re.search(self.backup_patterns['start'], msg):
                # Extract backup job details
                job_details = re.search(r'vzdump ([\d\s]+)', msg)
                if job_details:
                    current_job = {
                        'vms': job_details.group(1).split(),
                        'start_time': self._extract_timestamp(msg),
                        'vm_times': {},
                        'successful': False
                    }
            
            elif current_job and re.search(self.backup_patterns['vm_start'], msg):
                vm_id = re.search(self.backup_patterns['vm_start'], msg).group(1)
                current_job['vm_times'][vm_id] = {'start': self._extract_timestamp(msg)}
            
            elif current_job and re.search(self.backup_patterns['vm_finish'], msg):
                vm_id, duration = re.search(self.backup_patterns['vm_finish'], msg).groups()
                if vm_id in current_job['vm_times']:
                    current_job['vm_times'][vm_id]['duration'] = duration
            
            elif current_job and re.search(self.backup_patterns['success'], msg):
                current_job['successful'] = True
                current_job['end_time'] = self._extract_timestamp(msg)
                backups[self._extract_timestamp(msg).strftime("%Y-%m-%d %H:%M:%S")] = current_job
                current_job = None
        
        return backups

    def generate_insights(self, logs: Dict) -> Dict:
        """Generate insights from the logs"""
        insights = {
            'backup_summary': self._analyze_backup_performance(logs.get('grouped_messages', {}).get('info', {}).get('backup', [])),
            'error_patterns': self._analyze_error_patterns(logs.get('unique_messages', {}).get('error', [])),
            'service_status': self._analyze_service_status(logs)
        }
        return insights

    def _analyze_backup_performance(self, backup_messages: List[str]) -> Dict:
        """Analyze backup performance"""
        backups = self.analyze_backups(backup_messages)
        
        if not backups:
            return {'status': 'No backup information found'}
            
        summary = {
            'total_backups': len(backups),
            'successful_backups': sum(1 for b in backups.values() if b.get('successful')),
            'average_duration': self._calculate_average_duration(backups),
            'vms_backed_up': set().union(*[set(b.get('vms', [])) for b in backups.values()]),
            'details': backups
        }
        
        return summary

    def _analyze_error_patterns(self, error_messages: List[str]) -> Dict:
        """Analyze error patterns"""
        error_types = defaultdict(int)
        for msg in error_messages:
            if 'docker' in msg.lower():
                error_types['docker'] += 1
            elif 'service' in msg.lower():
                error_types['service'] += 1
            elif 'permission' in msg.lower():
                error_types['permission'] += 1
            else:
                error_types['other'] += 1
                
        return dict(error_types)

    def _analyze_service_status(self, logs: Dict) -> Dict:
        """Analyze service status"""
        service_status = {}
        service_messages = logs.get('grouped_messages', {}).get('service', {})
        
        for service_name, messages in service_messages.items():
            if any(re.search(self.service_patterns['failed'], msg) for msg in messages):
                service_status[service_name] = 'Failed'
            elif any(re.search(self.service_patterns['stop'], msg) for msg in messages):
                service_status[service_name] = 'Stopped'
            elif any(re.search(self.service_patterns['start'], msg) for msg in messages):
                service_status[service_name] = 'Started'
                
        return service_status

    def format_insights(self, insights: Dict) -> str:
        """Format insights for display"""
        output = []
        
        output.append(f"\n{Fore.GREEN}=== System Insights ==={Style.RESET_ALL}\n")
        
        # Backup insights
        if insights.get('backup_summary'):
            output.append(f"{Fore.CYAN}Backup Analysis:{Style.RESET_ALL}")
            backup_sum = insights['backup_summary']
            if backup_sum.get('total_backups'):
                output.append(f"• Total backup jobs: {backup_sum['total_backups']}")
                output.append(f"• Successful backups: {backup_sum['successful_backups']}")
                output.append(f"• VMs backed up: {len(backup_sum['vms_backed_up'])}")
                if backup_sum.get('average_duration'):
                    output.append(f"• Average duration: {backup_sum['average_duration']}")
                
                # Detailed backup information
                output.append("\nDetailed Backup Information:")
                for timestamp, backup in backup_sum.get('details', {}).items():
                    status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if backup['successful'] else f"{Fore.RED}✗{Style.RESET_ALL}"
                    output.append(f"{status} {timestamp}: {len(backup['vms'])} VMs")
            else:
                output.append("No backup jobs found in the analyzed time period")
        
        # Error pattern insights
        if insights.get('error_patterns'):
            output.append(f"\n{Fore.CYAN}Error Patterns:{Style.RESET_ALL}")
            for error_type, count in insights['error_patterns'].items():
                output.append(f"• {error_type.title()}: {count} occurrences")
        
        # Service status insights
        if insights.get('service_status'):
            output.append(f"\n{Fore.CYAN}Service Status:{Style.RESET_ALL}")
            for service, status in insights['service_status'].items():
                output.append(f"• {service}: {status}")
        
        return "\n".join(output)

    def _extract_timestamp(self, msg: str) -> datetime:
        """Extract timestamp from log message"""
        timestamp_match = re.match(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})', msg)
        if timestamp_match:
            try:
                current_year = datetime.now().year
                return datetime.strptime(f"{current_year} {timestamp_match.group(1)}", "%Y %b %d %H:%M:%S")
            except ValueError:
                return datetime.now()
        return datetime.now()

    def _calculate_average_duration(self, backups: Dict) -> str:
        """Calculate average backup duration"""
        durations = []
        for backup in backups.values():
            if backup.get('start_time') and backup.get('end_time'):
                duration = backup['end_time'] - backup['start_time']
                durations.append(duration.total_seconds())
        
        if durations:
            avg_seconds = sum(durations) / len(durations)
            minutes = int(avg_seconds // 60)
            seconds = int(avg_seconds % 60)
            return f"{minutes}m {seconds}s"
        return "unknown"
