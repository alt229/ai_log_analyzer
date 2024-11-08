# ai_analyzer.py
from anthropic import Anthropic
import json
from typing import List, Dict, Union
import os

class AILogAnalyzer:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("Anthropic API key is required. Set ANTHROPIC_API_KEY environment variable or pass it directly.")
        
        self.client = Anthropic(api_key=self.api_key)
    
    def analyze_logs(self, logs: Dict, system_info: Dict = None) -> Dict:
        """Analyze logs using Claude API and return recommendations"""
        
        # Convert any sets to lists for JSON serialization
        logs = self._prepare_json_serializable(logs)
        if system_info:
            system_info = self._prepare_json_serializable(system_info)
        
        # Prepare the context for Claude
        context = self._prepare_context(logs, system_info)
        
        try:
            response = self.client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=4096,
                temperature=0,
                system="""You are an expert system administrator analyzing Proxmox/Linux cluster logs.
                         You should focus particularly on cluster health, high availability status,
                         backup performance, and service stability.

                         Structure your response exactly like this:
                         === Overall Assessment ===
                         [1-2 sentence summary of system state]

                         === Critical Issues ===
                         [List any critical issues, if none state "No critical issues detected"]

                         === Service Issues ===
                         [List service-related issues]

                         === Recommendations ===
                         [Specific actions to take]

                         === Preventive Measures ===
                         [Ways to prevent similar issues]
                         """,
                messages=[{
                    "role": "user",
                    "content": context
                }]
            )
            
            if not response or not response.content:
                return {
                    'summary': "No response received from AI analysis",
                    'severity': "error",
                    'categories': {}
                }

            # Get the content as string
            content = str(response.content)
            
            # Extract sections
            sections = self._parse_sections(content)
            
            severity = self._determine_severity(content)
            
            return {
                'summary': content,
                'severity': severity,
                'sections': sections
            }
            
        except Exception as e:
            return {
                'summary': f"AI analysis failed: {str(e)}",
                'severity': "error",
                'sections': {
                    'Critical Issues': [str(e)]
                }
            }

    def _parse_sections(self, content: str) -> Dict[str, List[str]]:
        """Parse the response into sections"""
        sections = {}
        current_section = None
        current_items = []
        
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Check for section headers
            if line.startswith('===') and line.endswith('==='):
                if current_section and current_items:
                    sections[current_section] = current_items
                current_section = line.strip('= ')
                current_items = []
            elif line.startswith(('-', '•', '*', '1.', '2.', '3.')):
                if current_section:
                    current_items.append(line.lstrip('-•* 123.').strip())
            elif current_section and line:
                current_items.append(line)
        
        # Add the last section
        if current_section and current_items:
            sections[current_section] = current_items
            
        return sections

    def _prepare_json_serializable(self, obj: Union[Dict, List, set, str, int, float, bool, None]) -> Union[Dict, List, str, int, float, bool, None]:
        """Convert objects to JSON serializable format"""
        if isinstance(obj, dict):
            return {k: self._prepare_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, set)):
            return [self._prepare_json_serializable(v) for v in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        return str(obj)

    def _prepare_context(self, logs: Dict, system_info: Dict = None) -> str:
        """Prepare log data for AI analysis"""
        context_parts = []
        
        # Add system information if available
        if system_info:
            context_parts.extend([
                "System Information:",
                json.dumps(system_info, indent=2),
                ""
            ])
        
        # Add log summary
        context_parts.extend([
            "Log Analysis Summary:",
            f"Total issues found: {sum(logs.get('alerts', {}).values())}",
            ""
        ])
        
        # Add detailed logs
        context_parts.append("Detailed Logs:")
        
        if logs.get('grouped_messages'):
            for issue_type, groups in logs['grouped_messages'].items():
                for group_name, messages in groups.items():
                    context_parts.append(f"\n{issue_type.upper()} - {group_name}:")
                    # Limit to first 5 messages per group to avoid overwhelming the AI
                    for msg in list(messages)[:5]:
                        context_parts.append(f"  - {msg}")
        
        if logs.get('unique_messages'):
            for issue_type, messages in logs['unique_messages'].items():
                context_parts.append(f"\n{issue_type.upper()} - Unique Messages:")
                for msg in messages:
                    context_parts.append(f"  - {msg}")
        
        return "\n".join(context_parts)

    def _determine_severity(self, content: str) -> str:
        """Determine overall severity based on AI response"""
        content_lower = content.lower()
        
        if any(word in content_lower for word in [
            "critical", "immediate attention", "severe", "urgent", "failure",
            "lost lock", "cluster issue", "ha failure"
        ]):
            return "critical"
        elif any(word in content_lower for word in [
            "warning", "attention needed", "moderate", "should be addressed"
        ]):
            return "warning"
        elif "healthy" in content_lower or "no significant issues" in content_lower:
            return "info"
        return "info"
        
class ChatGPTProvider(AIProvider):
    def __init__(self, api_key: str = None, max_examples: int = 3):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.max_examples = max_examples
        if not self.api_key:
            raise ValueError("OpenAI API key is required. Set OPENAI_API_KEY environment variable or pass it directly.")
        self.client = openai.OpenAI(api_key=self.api_key)

    def _prepare_data(self, logs: Dict) -> str:
        """Reduce data size by limiting examples and removing redundancy"""
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
                # Only include first few examples
                for msg in messages[:self.max_examples]:
                    summary.append(f"Example: {msg}")
        
        # Add alert counts
        alerts = logs.get('alerts', {})
        summary.append("\nAlert Totals:")
        for alert_type, count in alerts.items():
            summary.append(f"{alert_type}: {count}")
        
        return "\n".join(summary)

    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        # Prepare reduced dataset
        log_summary = self._prepare_data(logs)
        
        response = self.client.chat.completions.create(
            model="gpt-4-1106-preview",  
            messages=[
                {"role": "system", "content": """You are an expert system administrator analyzing logs.
                    Focus on identifying patterns and providing actionable recommendations.
                    Provide analysis in the following format:
                    === Overall Assessment ===
                    === Critical Issues ===
                    === Service Issues ===
                    === Recommendations ===
                    === Preventive Measures ==="""},
                {"role": "user", "content": f"Analyze these logs:\n{log_summary}"}
            ],
            temperature=0
        )
        return self._parse_response(response.choices[0].message.content)