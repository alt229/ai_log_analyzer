# AI Log Analyzer

A powerful log analysis tool that combines system log collection with AI-powered insights. Supports local and remote log collection, Docker container logs, and multiple AI providers (Claude, ChatGPT, and Gemini).

## Features

- **Log Collection**
  - Local system logs
  - Remote system logs via SSH
  - Docker container logs
  - Support for custom Docker socket paths

- **Flexible Filtering**
  - Filter by severity (error, warning, info)
  - Group similar messages
  - Exclude specific message types
  - Summary view option

- **AI Analysis**
  - Multiple AI provider support (Claude, ChatGPT, Gemini)
  - Comparative analysis across providers
  - Customizable analysis depth
  - Save analysis results to file

- **Docker Integration**
  - Container log collection
  - Container stats collection
  - Custom socket path support
  - Container filtering

## Installation

1. Clone the repository:
```bash
git clone https://github.com/alt229/ai_log_analyzer.git
cd ai-log-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Before using the AI features, you'll need to set up your API keys:

```bash
# Set API keys
python main.py --set-api-key claude your-claude-key
python main.py --set-api-key chatgpt your-openai-key
python main.py --set-api-key gemini your-google-key

# View current configuration
python main.py --show-config

# Reset to defaults
python main.py --reset-config
```

Configuration is stored in `~/.config/ai_logs/config.yaml`.

## Usage Examples

### Basic Log Analysis

```bash
# Analyze local logs for the last hour
python main.py -t 1

# Show only errors
python main.py -t 1 --only-errors

# Full message display
python main.py -t 1 --full

# Summary view
python main.py -t 1 --summary
```

### Remote Log Analysis

```bash
# Analyze remote host logs
python main.py -t 1 --host server1.example.com --user admin --key ~/.ssh/id_rsa

# With AI analysis
python main.py -t 1 --host server1.example.com --user admin --key ~/.ssh/id_rsa --ai claude
```

### Docker Log Analysis

```bash
# Analyze all container logs
python main.py -t 1 --host server1.example.com --user admin --docker

# Specific container
python main.py -t 1 --host server1.example.com --user admin --docker --container nginx

# Custom Docker socket
python main.py -t 1 --host server1.example.com --user admin --docker --docker-socket /run/user/1000/docker.sock
```

### AI Analysis

```bash
# Basic AI analysis
python main.py -t 1 --ai claude

# Compare multiple AI providers
python main.py -t 1 --ai claude --compare

# Save analysis to file
python main.py -t 1 --ai claude -o analysis.txt
```

## Options

```
Time options:
  -t, --time HOURS         Number of hours to look back (default: 1)

Remote connection options:
  --host HOST             Remote host to analyze logs from
  --user USER             SSH username for remote host
  --port PORT             SSH port (default: 22)
  --key KEY              Path to SSH private key file

Output options:
  --no-color             Disable colored output
  --json                 Output results as JSON
  --full                 Show full messages without truncation
  -o, --output FILE      Write output to file
  --debug                Show debug information
  --summary              Show summarized output

Docker options:
  --docker               Include Docker container logs
  --container NAME       Specific container to analyze
  --no-container-stats   Skip container stats collection
  --docker-socket PATH   Path to Docker socket

AI analysis options:
  --ai PROVIDER          Enable AI analysis (claude, gemini, or chatgpt)
  --api-key KEY          API key for chosen AI provider
  --system-info FILE     Path to JSON file containing system information
  --compare              Compare analyses from all configured AI providers
```

## Requirements

- Python 3.8+
- Required packages (see requirements.txt):
  - pyyaml
  - colorama
  - paramiko
  - anthropic
  - openai
  - google-generativeai
  - docker

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## ToDo
Add windows event viewer support



## Authors

Erin Scott (but mostly Claude 3.5)

## Acknowledgments

- Thanks to Anthropic, OpenAI, and Google for their AI APIs!