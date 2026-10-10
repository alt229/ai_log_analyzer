# analyzer.py
# History:
# 2026-10-09 - Script Wrangler: Linux/journalctl process names containing
#   - . / @ (sshd-session, systemd-logind, postfix/smtpd) are read whole
#   instead of becoming 'unknown'; noise_filters.py changed in step.
import re
from datetime import datetime
from collections import defaultdict
from colorama import init, Fore, Style
import json
from log_dedup import LogDedup

# Initialize colorama for cross-platform colored output
init()

# macOS syslog shape: "2026-10-08 12:00:00.123456-0700  localhost Bartender 6[123]:"
# (process names may contain spaces)
MAC_SYSLOG_PROC = re.compile(
    r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[-+]\d{4}\s+\S+\s+(\S[^\[\]]*?)\[\d+\]:')

class LogAnalyzer:
    def __init__(self, use_color=True, output_file=None, output_json=False, 
                 show_full=False, debug=False, show_levels=None, ai_examples=1):
        self.use_color = use_color
        self.output_file = output_file
        self.output_json = output_json
        self.show_full = show_full
        self.debug = debug
        self.show_levels = show_levels or {'error', 'warning', 'info'}
        self.ai_examples = ai_examples   # raw example lines per pattern for the AI
        self.report_notes = []   # extra lines from main.py: noise filters, changes vs baseline
        
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
        self.total_matches = 0      # matched lines (the same set the AI digest counts)
        self.distinct_matches = 0   # of those, new messages per group (the old count)
        # Every matched line, grouped into patterns with counts (what the AI gets)
        self.dedup = LogDedup(keep_examples=self.ai_examples)

    def analyze_line(self, line):
        """Analyze a single log line for patterns"""
        if not line.strip():
            return

        self.total_lines_processed += 1

        # Extract process name for better grouping: the full name from macOS
        # ndjson (collector.LogLine), else the macOS syslog shape, else the
        # Linux "ident[pid]:" (ident may have - . / @: sshd-session,
        # postfix/smtpd; same as noise_filters._PLAIN_PROC, keep in step)
        process_name = getattr(line, 'process', None)
        if not process_name:
            process_match = MAC_SYSLOG_PROC.match(line) or re.search(r'\s([\w./@-]+)\[\d+\]:', line)
            process_name = process_match.group(1) if process_match else 'unknown'
        # 'critical' (fault) or 'error' when the macOS log type says so, else None
        level = getattr(line, 'level', None)

        matched = False
        recorded = False   # into self.dedup once, under its most severe type
        for issue_type, config in self.patterns.items():
            if issue_type not in self.show_levels:
                continue

            # A macOS error/fault counts as an error by its log type, whatever
            # its wording (and only as an error); other lines go by keywords
            hit = (issue_type == 'error') if level else re.search(config['pattern'], line, re.IGNORECASE)
            if hit:
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

                if not recorded:
                    self.dedup.add(level or issue_type, process_name, line)
                    recorded = True
                    self.total_matches += 1   # once per line, like the dedup

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
                    self.distinct_matches += 1

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
        
        # Notes from main.py (noise filter count, changes vs baseline)
        output.extend(self.report_notes)

        output.append(f"\nTotal lines processed: {self.total_lines_processed}")
        output.append(f"Total matches found: {self.total_matches} lines "
                      f"({self.distinct_matches} distinct messages)\n")
        
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
            output.append(self.colorize(f"{issue_type}: {count} distinct message(s)", color))
            
        if self.show_full:
            output.append("\nNote: Showing full messages (--full flag is enabled)")

        return "\n".join(output)

    def colorize(self, text, color):
        """Apply color if enabled"""
        if self.use_color:
            return f"{color}{text}{Style.RESET_ALL}"
        return text

    def get_results(self, summarize: bool = False) -> dict:
        """Get the analysis results, including any Windows summary if present."""
        result = {
            'alerts': dict(self.alerts),
            'grouped_messages': dict(self.grouped_messages),
            'unique_messages': dict(self.unique_messages),
            'stats': {
                'total_lines': self.total_lines_processed,
                'total_matches': self.total_matches,
                'distinct_matches': self.distinct_matches
            }
        }
        # Include Windows Event Log summary if it was collected
        win_summary = getattr(self, '_windows_summary', None)
        if win_summary:
            result['_windows_summary'] = win_summary
        return result

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
