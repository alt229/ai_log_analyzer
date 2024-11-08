# analyzer.py
import re
from datetime import datetime
from collections import defaultdict
from colorama import init, Fore, Style
import json

# Initialize colorama for cross-platform colored output
init()

class LogAnalyzer:
    def __init__(self, use_color=True, output_file=None, output_json=False, 
                 show_full=False, debug=False, show_levels=None):
        self.use_color = use_color
        self.output_file = output_file
        self.output_json = output_json
        self.show_full = show_full
        self.debug = debug
        self.show_levels = show_levels or {'error', 'warning', 'info'}
        
        # Enhanced patterns with better filtering
        self.patterns = {
            'error': {
                'pattern': r'(?i)(error|failure|failed|fatal|crit)',
                'ignore': [
                    r'No error',
                    r'Successfully|success',
                    r'error reports when automatic reporting is enabled',
                    r'GET /features',
                    r'GET /settings',
                    r'com\.apple\.wifi\..*error.*successfully',
                    r'INFO:.*backup job',
                    r'INFO:.*starting',
                    r'INFO: .*'
                ],
                'group': {
                    # macOS-specific groups
                    'coredata': r'CoreData.*error',
                    'cloudkit': r'CloudKitDaemon.*error',
                    'kernel': r'kernel\[\d+\].*error',
                    'wifi': r'(airportd|WiFiManager).*error',
                    'system': r'(runningboardd|containermanagerd|softwareupdated).*error',
                    # Linux/Proxmox specific groups
                    'cluster': r'(corosync|totem|cpg_|cluster).*failed',
                    'ha': r'(ha_manager_lock|ha_agent.*lock).*failed',
                    'storage': r'(storage|backup|restore).*failed',
                    'network': r'(network|connection|socket).*failed',
                    'permission': r'.*permission denied|not permitted',
                }
            },
            'warning': {
                'pattern': r'(?i)(warning|warn)',
                'ignore': [
                    r'GET /settings',
                    r'GET /features',
                    r'/desktop_extensions',
                    r'BackendAPI',
                    r'".*":\s*{.*}'
                ],
                'group': {
                    'cluster': r'cluster.*warning',
                    'network': r'network.*warning',
                    'resource': r'resource.*warning'
                }
            },
            'info': {
                'pattern': r'INFO:',
                'ignore': [],
                'group': {
                    'backup': r'INFO:.*backup',
                    'service': r'INFO:.*service',
                    'cluster': r'INFO:.*(cluster|node)',
                }
            }
        }
        
        self.reset_counters()

    def reset_counters(self):
        """Reset all counters and storage"""
        self.alerts = defaultdict(int)
        self.unique_messages = defaultdict(set)
        self.grouped_messages = defaultdict(lambda: defaultdict(list))
        self.total_lines_processed = 0
        self.total_matches = 0

    def analyze_line(self, line):
        """Analyze a single log line for patterns"""
        if not line.strip():
            return

        self.total_lines_processed += 1

        # Extract process name for better grouping
        process_match = re.search(r'\s(\w+)\[\d+\]:', line)
        process_name = process_match.group(1) if process_match else 'unknown'

        matched = False
        for issue_type, config in self.patterns.items():
            if issue_type not in self.show_levels:
                continue

            if re.search(config['pattern'], line, re.IGNORECASE):
                # Check ignore patterns
                should_ignore = False
                for ignore in config['ignore']:
                    if re.search(ignore, line, re.IGNORECASE):
                        if self.debug:
                            print(f"DEBUG: Ignoring line from process {process_name}")
                        should_ignore = True
                        break
                
                if should_ignore:
                    continue

                # Check group patterns
                grouped = False
                for group_name, pattern in config['group'].items():
                    if re.search(pattern, line, re.IGNORECASE):
                        # Create a summary of the error
                        summary = self._create_error_summary(line, process_name)
                        if summary not in self.grouped_messages[issue_type][group_name]:
                            self.grouped_messages[issue_type][group_name].append(summary)
                            matched = True
                        grouped = True
                        if self.debug:
                            print(f"DEBUG: Added to group '{group_name}':\n{line}")
                        break
                
                # If not grouped by pattern, group by process
                if not grouped:
                    summary = self._create_error_summary(line, process_name)
                    process_group = f"process_{process_name}"
                    if summary not in self.grouped_messages[issue_type][process_group]:
                        self.grouped_messages[issue_type][process_group].append(summary)
                        matched = True
                        if self.debug:
                            print(f"DEBUG: Added as unique {issue_type}:\n{line}")

                if matched:
                    self.alerts[issue_type] += 1
                    self.total_matches += 1

    def _create_error_summary(self, line: str, process_name: str) -> str:
        """Create a summary of the error message, removing variable parts"""
        # Remove timestamp
        line = re.sub(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[-+]\d{4}', 'TIMESTAMP', line)
        # Remove process IDs
        line = re.sub(r'\[\d+\]', '[PID]', line)
        # Remove operation IDs (common in CloudKit errors)
        line = re.sub(r'Operation [A-F0-9-]+', 'Operation ID', line)
        # Remove specific error codes
        line = re.sub(r'error \d+', 'error CODE', line)
        return line

    def clean_message(self, message):
        """Clean message for display"""
        # Remove timestamps in square brackets that appear in the middle of the message
        message = re.sub(r'\s+\[\d{2}:\d{2}:\d{2}.*?\](?!$)', ' ', message)
        # Only truncate if show_full is False and message is too long
        if not self.show_full and len(message) > 120:
            return message[:117] + "..."
        return message

    def format_output(self):
        """Format the analysis results"""
        output = []
        
        # Header with stats
        output.append("\n" + "="*50)
        output.append(f"{Fore.GREEN}Log Analysis Results{Style.RESET_ALL}")
        output.append("="*50)
        
        # Add active filters to output if not showing everything
        if self.show_levels != {'error', 'warning', 'info'}:
            output.append(f"\n{Fore.CYAN}Active Filters:{Style.RESET_ALL}")
            output.append(f"Showing only: {', '.join(sorted(self.show_levels))}")
        
        output.append(f"\nTotal lines processed: {self.total_lines_processed}")
        output.append(f"Total matches found: {self.total_matches}\n")
        
        # Grouped messages
        for issue_type, groups in self.grouped_messages.items():
            if issue_type not in self.show_levels:
                continue
                
            for group_name, messages in groups.items():
                if messages:
                    count = len(messages)
                    output.append(f"\n{Fore.YELLOW}[{issue_type.upper()}] {group_name}: {count} occurrence(s){Style.RESET_ALL}")
                    if self.show_full:
                        output.append("Messages:")
                        for msg in messages:
                            output.append(f"  {self.clean_message(msg)}")
                    else:
                        output.append(f"Example: {self.clean_message(messages[0])}")

        # Unique messages
        for issue_type, messages in self.unique_messages.items():
            if issue_type not in self.show_levels:
                continue
                
            for msg in messages:
                output.append(self.colorize(f"[{issue_type.upper()}] {self.clean_message(msg)}", 
                    Fore.RED if issue_type == 'error' else 
                    Fore.YELLOW if issue_type == 'warning' else 
                    Fore.BLUE))

        # Summary
        output.append("\n" + self.colorize("=== Summary ===", Fore.GREEN))
        for issue_type, count in sorted(self.alerts.items()):
            if issue_type not in self.show_levels:
                continue
                
            color = Fore.RED if issue_type == 'error' else Fore.YELLOW if issue_type == 'warning' else Fore.BLUE
            output.append(self.colorize(f"{issue_type}: {count} total issues", color))
            
        if self.show_full:
            output.append("\nNote: Showing full messages (--full flag is enabled)")

        return "\n".join(output)

    def colorize(self, text, color):
        """Apply color if enabled"""
        if self.use_color:
            return f"{color}{text}{Style.RESET_ALL}"
        return text

    def get_results(self, summarize: bool = False) -> dict:
        """Get the analysis results"""
        if summarize:
            # Return summarized log data
            return {
                'alerts': dict(self.alerts),
                'grouped_messages': dict(self.grouped_messages),
                'unique_messages': dict(self.unique_messages),
                'stats': {
                    'total_lines': self.total_lines_processed,
                    'total_matches': self.total_matches
                }
            }
        else:
            # Return raw log data
            return {
                'alerts': dict(self.alerts),
                'grouped_messages': dict(self.grouped_messages),
                'unique_messages': dict(self.unique_messages),
                'stats': {
                    'total_lines': self.total_lines_processed,
                    'total_matches': self.total_matches
                }
            }

    def run(self, collector, hours=1):
        """Main analysis loop"""
        print(f"Analyzing logs for the past {hours} hour(s)...")
        
        # Get logs using the collector
        logs = collector.get_logs(hours)
        
        if not logs:
            print("Warning: No logs were collected!")
            return
            
        print(f"Processing {len(logs)} log lines...")
        
        # Analyze each log line
        for line in logs:
            self.analyze_line(line)
        
        # Format and output results
        output = self.format_output()
        
        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write(output)
        else:
            print(output)
