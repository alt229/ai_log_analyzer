# ai_providers.py
from abc import ABC, abstractmethod
import os
import json
from typing import Dict, Optional
import google.generativeai as genai
import openai
from anthropic import Anthropic
from analyzer import LogAnalyzer

class AIProvider(ABC):
    """Base class for AI providers"""
    @abstractmethod
    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        pass

class ClaudeProvider(AIProvider):
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("Claude API key is required. Set ANTHROPIC_API_KEY environment variable or pass it directly.")
        self.client = Anthropic(api_key=self.api_key)

    def _prepare_prompt(self, logs: Dict, system_info: Optional[Dict] = None) -> str:
        """Prepare the prompt for Claude"""
        parts = ["Please analyze these system logs:"]
        
        # Add basic statistics
        stats = logs.get('stats', {})
        parts.append(f"\nStatistics:")
        parts.append(f"Total lines processed: {stats.get('total_lines', 0)}")
        parts.append(f"Total matches found: {stats.get('total_matches', 0)}")
        
        # Add grouped messages
        grouped = logs.get('grouped_messages', {})
        for issue_type, groups in grouped.items():
            parts.append(f"\n{issue_type.upper()} Groups:")
            for group_name, messages in groups.items():
                parts.append(f"\n{group_name}: {len(messages)} occurrences")
                # Add up to 3 examples
                for msg in list(messages)[:3]:
                    parts.append(f"Example: {msg}")
        
        # Add system info if provided
        if system_info:
            parts.append("\nSystem Information:")
            parts.append(json.dumps(system_info, indent=2))
        
        return "\n".join(parts)

    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        try:
            prompt = self._prepare_prompt(logs, system_info)
            
            response = self.client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=4096,
                temperature=0,
                system="You are an expert system administrator analyzing logs. Format your response with these exact sections: === Overall Assessment === (brief overview) === Critical Issues === (list major problems) === Service Issues === (list service problems) === Recommendations === (list actions to take) === Preventive Measures === (list prevention steps)",
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            if not response or not response.content:
                raise ValueError("No response received from Claude")
            
            content = str(response.content)
            severity = self._determine_severity(content)
            
            return {
                'summary': content,
                'severity': severity
            }
            
        except Exception as e:
            raise RuntimeError(f"Error with Claude: {str(e)}")

    def _determine_severity(self, content: str) -> str:
        """Determine severity based on content"""
        content = content.lower()
        if any(word in content for word in ["critical", "severe", "urgent", "failure", "error"]):
            return "critical"
        elif any(word in content for word in ["warning", "attention", "caution", "moderate"]):
            return "warning"
        return "info"
        
class GeminiProvider(AIProvider):
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('GOOGLE_API_KEY')
        if not self.api_key:
            raise ValueError("Google API key is required. Set GOOGLE_API_KEY environment variable or pass it directly.")
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-pro')

    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        try:
            prompt = self._prepare_prompt(logs, system_info)
            response = self.model.generate_content(prompt)
            return self._parse_response(response.text)
        except Exception as e:
            raise RuntimeError(f"Error with Gemini: {str(e)}")

    def _prepare_prompt(self, logs: Dict, system_info: Optional[Dict] = None) -> str:
        return """You are an expert system administrator analyzing logs. 
                 Please provide analysis in the following format:
                 === Overall Assessment ===
                 [Brief assessment]
                 === Critical Issues ===
                 [List critical issues]
                 === Service Issues ===
                 [List service issues]
                 === Recommendations ===
                 [List recommendations]
                 === Preventive Measures ===
                 [List preventive measures]

                 Logs to analyze:
                 """ + str(logs)
                 
    def _prepare_data(self, logs: Dict) -> str:
        """Reduce data size by limiting examples"""
        summary = []
        summary.append("Log Analysis Summary:")
    
        # Add statistics
        stats = logs.get('stats', {})
        summary.append(f"Total lines processed: {stats.get('total_lines', 0)}")
        summary.append(f"Total matches found: {stats.get('total_matches', 0)}\n")
    
        # Add grouped messages with limited examples
        grouped = logs.get('grouped_messages', {})
        for issue_type, groups in grouped.items():
            summary.append(f"\n{issue_type.upper()} Groups:")
            for group_name, messages in groups.items():
                count = len(messages)
                summary.append(f"\n{group_name}: {count} occurrences")
                for msg in messages[:self.max_examples]:
                    summary.append(f"Example: {msg}")
    
        return "\n".join(summary)

    def _parse_response(self, content: str) -> Dict:
        """Parse the AI response into a structured format"""
        return {
            'summary': content,
            'severity': self._determine_severity(content)
        }

    def _determine_severity(self, content: str) -> str:
        """Determine severity based on content"""
        content_lower = content.lower()
        if any(word in content_lower for word in ["critical", "urgent", "severe"]):
            return "critical"
        elif any(word in content_lower for word in ["warning", "attention", "moderate"]):
            return "warning"
        return "info"    
                 
class ChatGPTProvider(AIProvider):
    def __init__(self, api_key: str = None, max_examples: int = 3):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.max_examples = max_examples
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set OPENAI_API_KEY environment variable or pass it directly.")
        self.client = openai.OpenAI(api_key=self.api_key)

    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",  # or "gpt-3.5-turbo" for faster/cheaper analysis
                messages=[
                    {"role": "system", "content": """You are an expert system administrator analyzing logs.
                        Provide analysis in the following format:
                        === Overall Assessment ===
                        === Critical Issues ===
                        === Service Issues ===
                        === Recommendations ===
                        === Preventive Measures ==="""},
                    {"role": "user", "content": f"Analyze these logs:\n{logs}"}
                ],
                temperature=0
            )
            return self._parse_response(response.choices[0].message.content)
        except Exception as e:
            raise RuntimeError(f"Error with ChatGPT: {str(e)}")
    def _parse_response(self, content: str) -> Dict:
        return {
            'summary': content,
            'severity': self._determine_severity(content)
        }

    def _determine_severity(self, content: str) -> str:
        content_lower = content.lower()
        if any(word in content_lower for word in ["critical", "urgent", "severe"]):
            return "critical"
        elif any(word in content_lower for word in ["warning", "attention", "moderate"]):
            return "warning"
        return "info"

def get_ai_provider(provider_name: str, api_key: str = None) -> AIProvider:
    """Factory function to get the appropriate AI provider"""
    providers = {
        'claude': ClaudeProvider,
        'gemini': GeminiProvider,
        'chatgpt': ChatGPTProvider
    }
    
    if provider_name not in providers:
        raise ValueError(f"Unknown AI provider: {provider_name}. Available providers: {', '.join(providers.keys())}")
    
    return providers[provider_name](api_key)
