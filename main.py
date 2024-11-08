#!/usr/bin/env python3
# main.py
import argparse
import sys
import os
import json
from dataclasses import dataclass
from typing import Optional, Dict, List
from colorama import Fore, Style

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from collector import LogCollector
from analyzer import LogAnalyzer
from ai_providers import get_ai_provider
from local_insights import LocalInsights
from config import Config

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Advanced log analyzer for system logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Analyze local logs for the last hour
    log_analyzer -t 1

    # Analyze local logs, errors only
    log_analyzer -t 1 --only-errors

    # Remote analysis with custom SSH key
    log_analyzer -t 1 --host server1.example.com --user admin --key ~/.ssh/id_rsa

    # AI analysis with different providers
    log_analyzer -t 1 --ai claude --api-key your-key
    log_analyzer -t 1 --ai gemini --api-key your-key
    log_analyzer -t 1 --ai chatgpt --api-key your-key
        """)

    # Time window options
    parser.add_argument('-t', '--time', type=float, default=1,
                      help='Number of hours to look back (default: 1)')

    # Remote connection options
    remote_group = parser.add_argument_group('remote connection options')
    remote_group.add_argument('--host', help='Remote host to analyze logs from')
    remote_group.add_argument('--user', help='SSH username for remote host')
    remote_group.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    remote_group.add_argument('--key', help='Path to SSH private key file')

    # Output options
    output_group = parser.add_argument_group('output options')
    output_group.add_argument('--no-color', action='store_true', help='Disable colored output')
    output_group.add_argument('--json', action='store_true', help='Output results as JSON')
    output_group.add_argument('--full', action='store_true', help='Show full messages without truncation')
    output_group.add_argument('-o', '--output', help='Write output to file')
    output_group.add_argument('--debug', action='store_true', help='Show debug information')
    output_group.add_argument('--summary', action='store_true', help='Show summarized output')

    # Severity filter options
    filter_group = parser.add_argument_group('severity filter options')
    filter_group.add_argument('--only-errors', action='store_true',
                          help='Show only error messages')
    filter_group.add_argument('--only-warnings', action='store_true',
                          help='Show only warning messages')
    filter_group.add_argument('--only-info', action='store_true',
                          help='Show only info messages')
    filter_group.add_argument('--ignore', nargs='+', choices=['info', 'warnings', 'errors'],
                          help='Ignore specific message types')

    # AI analysis options
    ai_group = parser.add_argument_group('AI analysis options')
    ai_group.add_argument('--ai', metavar='PROVIDER',
                       help='Enable AI analysis using specified provider (claude, gemini, or chatgpt)')
    ai_group.add_argument('--max-examples', type=int, default=3,
                       help='Maximum number of examples per error group to send to AI (default: 3)')
    ai_group.add_argument('--api-key', help='API key for chosen AI provider')
    ai_group.add_argument('--system-info', help='Path to JSON file containing system information')
    ai_group.add_argument('--compare', action='store_true',
                       help='Compare analyses from all configured AI providers')
                       
    config_group = parser.add_argument_group('configuration options')
    config_group.add_argument('--set-api-key', nargs=2, metavar=('PROVIDER', 'KEY'),
                          help='Set API key for specified provider')
    config_group.add_argument('--show-config', action='store_true',
                          help='Show current configuration')
    config_group.add_argument('--reset-config', action='store_true',
                          help='Reset configuration to defaults')
                          
    # Docker options
    docker_group = parser.add_argument_group('docker options')
    docker_group.add_argument('--docker', action='store_true',
                          help='Include Docker container logs')
    docker_group.add_argument('--container',
                          help='Specific container to analyze (default: all)')
    docker_group.add_argument('--no-container-stats', action='store_true',
                          help='Skip container stats collection')
    docker_group.add_argument('--docker-socket',
                          help='Path to Docker socket (default: /var/run/docker.sock)')

    return parser


def format_ai_recommendations(recommendations: Dict) -> str:
    """Format AI recommendations for display"""
    output = []
    
    output.append("\n" + "="*70)
    output.append(f"{Fore.GREEN}🔍 AI Analysis Results{Style.RESET_ALL}")
    output.append("="*70)
    
    # Add severity with icon
    severity = recommendations.get('severity', 'unknown').upper()
    severity_info = {
        'CRITICAL': (Fore.RED, '🔴'),
        'WARNING': (Fore.YELLOW, '⚠️'),
        'INFO': (Fore.BLUE, 'ℹ️'),
    }.get(severity, (Fore.WHITE, '❔'))
    
    output.append(f"\n{severity_info[0]}Severity: {severity_info[1]} {severity}{Style.RESET_ALL}")
    
    # Calculate timing between first and last errors
    times = []
    for type_msgs in recommendations.get('results', {}).values():
        for msg in type_msgs:
            if isinstance(msg, str) and 'Nov 07' in msg:  # Adjust date pattern as needed
                try:
                    time_str = msg.split()[3]  # Extract time part
                    times.append(time_str)
                except IndexError:
                    continue
    
    if times:
        first_time = min(times)
        last_time = max(times)
        output.append(f"\n{Fore.CYAN}🕒 Issue Timeline: {first_time} - {last_time}{Style.RESET_ALL}")
    
    # Format the detailed analysis
    if 'summary' in recommendations:
        content = str(recommendations['summary'])
        # Clean up TextBlock formatting
        content = content.replace("TextBlock(text='", "")
        content = content.replace("', type='text')", "")
        content = content.replace(" === ===", "===")
        content = content.replace("\\n", "\n")
        content = content.replace("[ ", "").replace(" ]", "")
        
        # Split into sections and format
        sections = content.split('===')
        for section in sections:
            section = section.strip()
            if not section:
                continue
            
            lines = section.split('\n', 1)
            if len(lines) > 0:
                title = lines[0].strip()
                content = lines[1].strip() if len(lines) > 1 else ""
                
                if title:
                    # Add icons for each section
                    section_icons = {
                        'Overall Assessment': '📊',
                        'Critical Issues': '🚨',
                        'Service Issues': '🔧',
                        'Recommendations': '💡',
                        'Preventive Measures': '🛡️'
                    }
                    icon = section_icons.get(title, '📝')
                    output.append(f"\n{Fore.CYAN}=== {icon} {title} ==={Style.RESET_ALL}")
                    
                    # Format bullet points and numbered items
                    for line in content.split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith(('-', '•')):
                            output.append(f"{Fore.YELLOW}  • {line.lstrip('-• ')}{Style.RESET_ALL}")
                        elif line[0].isdigit() and line[1] == '.':
                            output.append(f"{Fore.GREEN}  {line}{Style.RESET_ALL}")
                        else:
                            output.append(f"  {line}")

    return '\n'.join(output)



def main():
    parser = create_parser()
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
        
    args = parser.parse_args()
    
    # Initialize config
    try:
        config = Config()
    except Exception as e:
        print(f"{Fore.RED}Error initializing config: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

    # Handle configuration commands
    if args.set_api_key:
        provider, key = args.set_api_key
        config.set_api_key(provider, key)
        sys.exit(0)
    
    if args.show_config:
        config.show_config()
        sys.exit(0)
        
    if args.reset_config:
        config.reset_config()
        sys.exit(0)
    
    try:
        # Setup collector
        collector = LogCollector(
            host=args.host,
            user=args.user,
            port=args.port,
            key_file=args.key
        )
        
        # Determine which severity levels to show
        show_levels = set(['error', 'warning', 'info'])
        
        # Handle exclusive filters
        if args.only_errors:
            show_levels = {'error'}
        elif args.only_warnings:
            show_levels = {'warning'}
        elif args.only_info:
            show_levels = {'info'}
            
        # Handle ignore filters
        if args.ignore:
            for level in args.ignore:
                # Convert 'warnings' to 'warning' if needed
                level = level.rstrip('s')
                if level in show_levels:
                    show_levels.remove(level)

        # Create analyzer instance
        analyzer = LogAnalyzer(
            use_color=not args.no_color,
            output_file=args.output,
            output_json=args.json,
            show_full=args.full,
            debug=args.debug,
            show_levels=show_levels
        )
        
        # Run standard log analysis
        analyzer.run(collector, hours=args.time)

        # Handle Docker logs if requested
        if args.docker:
            if not args.host:
                print(f"{Fore.RED}Error: Docker collection requires SSH host (--host){Style.RESET_ALL}")
                sys.exit(1)
                
            try:
                from docker_collector import RemoteDockerLogCollector
                docker_config = config.get_docker_config()
                
                # Update config with command line socket path if provided
                if args.docker_socket:
                    docker_config['socket'] = args.docker_socket
                
                # Use the existing SSH connection from the collector
                docker_collector = RemoteDockerLogCollector(collector.ssh, docker_config)
                
                # Get Docker logs
                docker_logs = docker_collector.get_container_logs(
                    hours=args.time,
                    container_name=args.container if args.container else None
                )
                
                if not docker_logs:
                    print(f"{Fore.YELLOW}No Docker logs found{Style.RESET_ALL}")
                else:
                    # Get container stats if not disabled
                    container_stats = None
                    if not args.no_container_stats:
                        container_stats = docker_collector.get_container_stats(
                            container_name=args.container if args.container else None
                        )
                    
                    # Analyze Docker logs
                    for container, logs in docker_logs.items():
                        print(f"\nAnalyzing logs for container: {container}")
                        for line in logs:
                            analyzer.analyze_line(line)
                        
                    # Add container stats to system info for AI analysis
                    if container_stats and (args.ai or args.compare):
                        if 'system_info' not in locals():
                            system_info = {}
                        system_info['docker'] = container_stats
                        
            except Exception as e:
                print(f"{Fore.RED}Error collecting Docker logs: {str(e)}{Style.RESET_ALL}")
                if args.debug:
                    import traceback
                    traceback.print_exc()

        # Run AI analysis if requested
        if args.ai or args.compare:
            valid_providers = ['claude', 'gemini', 'chatgpt']
            
            if args.ai and args.ai.lower() not in valid_providers:
                print(f"\n{Fore.RED}Error: Invalid AI provider. Choose from: {', '.join(valid_providers)}{Style.RESET_ALL}")
                sys.exit(1)
            
            # Get API key from config if not provided in command line
            if args.ai and not args.api_key:
                args.api_key = config.get_api_key(args.ai.lower())
                if not args.api_key:
                    print(f"\n{Fore.YELLOW}No API key found for {args.ai}. Set it with:{Style.RESET_ALL}")
                    print(f"python main.py --set-api-key {args.ai} your-key-here")
                    sys.exit(1)
            
            try:
                from ai_providers import get_ai_provider

                # Load system info if provided
                if args.system_info:
                    try:
                        with open(args.system_info) as f:
                            if 'system_info' not in locals():
                                system_info = json.load(f)
                            else:
                                system_info.update(json.load(f))
                    except Exception as e:
                        print(f"{Fore.YELLOW}Error loading system info: {str(e)}{Style.RESET_ALL}")

                if args.compare:
                    # Run analysis with all providers
                    results = {}
                    for provider in valid_providers:
                        try:
                            # Get API key for each provider
                            provider_key = config.get_api_key(provider)
                            if not provider_key:
                                print(f"{Fore.YELLOW}Skipping {provider}: No API key found{Style.RESET_ALL}")
                                continue
                                
                            ai_provider = get_ai_provider(provider, provider_key)
                            print(f"\nRunning analysis with {provider.title()}...")
                            results[provider] = ai_provider.analyze_logs(
                                analyzer.get_results(args.summary), 
                                system_info if 'system_info' in locals() else None
                            )
                        except Exception as e:
                            print(f"Error with {provider}: {str(e)}")

                    # Print comparison
                    if results:
                        print("\n=== AI Analysis Comparison ===")
                        for provider, result in results.items():
                            print(f"\n{provider.title()} Analysis:")
                            print(format_ai_recommendations(result))
                    else:
                        print(f"\n{Fore.YELLOW}No AI analysis results available{Style.RESET_ALL}")
                else:
                    # Run analysis with single provider
                    try:
                        ai_provider = get_ai_provider(args.ai, args.api_key)
                        print(f"\nRunning AI analysis using {args.ai.title()}...")

                        # Get AI recommendations
                        recommendations = ai_provider.analyze_logs(
                            analyzer.get_results(args.summary), 
                            system_info if 'system_info' in locals() else None
                        )

                        # Print formatted recommendations
                        print(format_ai_recommendations(recommendations))

                        # Save to file if output is specified
                        if args.output:
                            with open(args.output, 'a') as f:
                                f.write('\n' + format_ai_recommendations(recommendations))
                    except Exception as e:
                        print(f"Error with {args.ai}: {str(e)}")
                        if args.debug:
                            import traceback
                            traceback.print_exc()
                            
            except ImportError as e:
                print(f"\n{Fore.YELLOW}Required packages missing. Install with:{Style.RESET_ALL}")
                print("pip install anthropic google-generativeai openai")
                sys.exit(1)
                
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
                
if __name__ == "__main__":
    main()
