# config.py
import os
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
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        
        if not os.path.exists(self.config_file):
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
            self.save_config(default_config)
            return default_config
            
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"{Fore.RED}Error loading config: {str(e)}{Style.RESET_ALL}")
            return self._load_config()  # Return default config if load fails

    def save_config(self, config):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
        except Exception as e:
            print(f"{Fore.RED}Error saving config: {str(e)}{Style.RESET_ALL}")

    def get_api_key(self, provider):
        """Get API key for specified provider"""
        return self.config.get('api_keys', {}).get(provider)

    def set_api_key(self, provider, key):
        """Set API key for specified provider"""
        if 'api_keys' not in self.config:
            self.config['api_keys'] = {}
        self.config['api_keys'][provider] = key
        self.save_config(self.config)
        print(f"{Fore.GREEN}API key for {provider} has been saved{Style.RESET_ALL}")

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

    def reset_config(self):
        """Reset configuration to defaults"""
        if os.path.exists(self.config_file):
            os.remove(self.config_file)
        self.config = self._load_config()
        print(f"{Fore.GREEN}Configuration has been reset to defaults{Style.RESET_ALL}")