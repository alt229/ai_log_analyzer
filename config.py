# config.py
import os
import time
import yaml
from pathlib import Path
from colorama import Fore, Style

class Config:
    def __init__(self):
        self.config_dir = os.path.expanduser("~/.config/ai_logs")
        self.config_file = os.path.join(self.config_dir, "config.yaml")
        self.config = self._load_config()

    def _load_config(self):
        """Load configuration from file or create default"""
        self.load_failed = False
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                # One message, then in-memory defaults (no recursion). The broken
                # file is NOT rewritten; save_config() refuses while load_failed.
                print(f"{Fore.RED}Error loading config: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Using built-in defaults for this run; "
                      f"{self.config_file} was left untouched.{Style.RESET_ALL}")
                self.load_failed = True

        if self.load_failed or not os.path.exists(self.config_file):
            default_config = {
                'api_keys': {
                    'claude': '',
                    'gemini': '',
                    'chatgpt': ''
                },
                'docker': {
                    'socket': '/var/run/docker.sock',    # Default Docker socket
                    'excluded_containers': [],           # Containers to exclude
                    'max_log_lines': 1000,              # Max lines per container
                    'include_stats': True,              # Whether to collect container stats
                    'log_filters': {                    # Patterns to filter logs
                        'include': [],
                        'exclude': []
                    }
                },
                'default_settings': {
                    'debug': False,
                    'color': True,
                    'summary': True,
                    'max_examples': 3
                }
            }
            if not self.load_failed:
                self.save_config(default_config)  # first run: write the defaults
            return default_config

    def save_config(self, config):
        """Save configuration to file. Returns True if it was written."""
        if getattr(self, 'load_failed', False):
            print(f"{Fore.RED}Not saving: {self.config_file} could not be read, so it is "
                  f"left untouched. Fix it by hand, or use --reset-config "
                  f"(keeps a backup).{Style.RESET_ALL}")
            return False
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        except Exception as e:
            print(f"{Fore.RED}Error saving config: {str(e)}{Style.RESET_ALL}")
            return False
        return True

    def get_api_key(self, provider):
        """Get API key for specified provider"""
        return self.config.get('api_keys', {}).get(provider)

    def set_api_key(self, provider, key):
        """Set API key for specified provider"""
        if 'api_keys' not in self.config:
            self.config['api_keys'] = {}
        self.config['api_keys'][provider] = key
        if not self.save_config(self.config):
            return False
        print(f"{Fore.GREEN}API key for {provider} has been saved{Style.RESET_ALL}")
        return True

    def get_docker_config(self):
        """Get Docker configuration"""
        return self.config.get('docker', {})

    def update_docker_config(self, updates: dict):
        """Update Docker configuration"""
        if 'docker' not in self.config:
            self.config['docker'] = {}
        self.config['docker'].update(updates)
        self.save_config(self.config)

    def get_default_settings(self):
        """Get default settings"""
        return self.config.get('default_settings', {})

    def set_default_setting(self, setting: str, value):
        """Set a default setting"""
        if 'default_settings' not in self.config:
            self.config['default_settings'] = {}
        self.config['default_settings'][setting] = value
        self.save_config(self.config)

    def show_config(self):
        """Display current configuration"""
        print(f"\n{Fore.CYAN}Current Configuration:{Style.RESET_ALL}")
        
        # Show API Keys (masked)
        print("\nAPI Keys:")
        for provider, key in self.config.get('api_keys', {}).items():
            masked_key = "********" if key else "Not set"
            print(f"  {provider}: {masked_key}")
        
        # Show Docker Config
        print("\nDocker Settings:")
        docker_config = self.config.get('docker', {})
        for key, value in docker_config.items():
            print(f"  {key}: {value}")
        
        # Show Default Settings
        print("\nDefault Settings:")
        default_settings = self.config.get('default_settings', {})
        for key, value in default_settings.items():
            print(f"  {key}: {value}")

    def reset_config(self, assume_yes=False):
        """Reset configuration to defaults. Asks first (unless assume_yes); the old
        file is renamed to a timestamped backup (mode 600), nothing is deleted.
        Returns True if reset."""
        if os.path.exists(self.config_file):
            if not assume_yes:
                try:
                    answer = input(f"Reset {self.config_file} to defaults? This removes all "
                                   f"stored API keys (the old file is kept as a backup). [y/N] ")
                except (EOFError, KeyboardInterrupt):
                    print()
                    answer = ''
                if answer.strip().lower() not in ('y', 'yes'):
                    print(f"{Fore.YELLOW}Reset cancelled; nothing changed.{Style.RESET_ALL}")
                    return False
            backup = f"{self.config_file}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
            if os.path.lexists(backup):
                # never overwrite an earlier backup (os.rename would replace it)
                print(f"{Fore.RED}{backup} already exists; nothing changed. "
                      f"Try again in a second.{Style.RESET_ALL}")
                return False
            try:
                os.chmod(self.config_file, 0o600)      # it holds API keys
                os.rename(self.config_file, backup)    # the old file becomes the backup
            except OSError as e:
                print(f"{Fore.RED}Could not move {self.config_file} to {backup} ({e}); "
                      f"nothing reset.{Style.RESET_ALL}")
                return False
            print(f"Backup saved to {backup} (mode 600)")
        self.config = self._load_config()
        print(f"{Fore.GREEN}Configuration has been reset to defaults{Style.RESET_ALL}")
        return True
