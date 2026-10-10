# ai_providers.py
from abc import ABC, abstractmethod
import os
import sys
import json
import re
from typing import Dict, Optional

# All AI library imports are lazy (inside __init__) so that a missing or
# deprecated package for one provider does not crash the program when
# you are using a different provider.


# ---------------------------------------------------------------------------
# Shared prompt builder
# ---------------------------------------------------------------------------

def _build_prompt(logs: Dict, system_info: Optional[Dict] = None) -> str:
    """Build an analysis prompt from structured log results."""
    parts = ["Please analyze these system logs and identify issues that need attention.\n"]

    if isinstance(logs, dict) and '_deep_dive' in logs:
        # Deep dive mode: the prompt is pre-built
        return logs['_deep_dive']
    elif isinstance(logs, str):
        # Pre-formatted string (e.g. Windows summary passed directly)
        parts.append(logs)
    elif logs.get('_ai_digest'):
        # De-duplicated patterns (log_dedup.py, built and size-capped by main.py)
        parts.append(logs['_ai_digest'])
        win_summary = logs.get('_windows_summary')
        if win_summary:
            parts.append(f"\n{win_summary}")
    else:
        stats = logs.get('stats', {})
        parts.append("=== Statistics ===")
        parts.append(f"Total lines processed : {stats.get('total_lines', 0)}")
        parts.append(f"Total matches found   : {stats.get('total_matches', 0)}")

        grouped = logs.get('grouped_messages', {})
        for issue_type, groups in grouped.items():
            parts.append(f"\n=== {issue_type.upper()} Groups ===")
            for group_name, messages in groups.items():
                parts.append(f"\n{group_name}: {len(messages)} occurrences")
                for msg in list(messages)[:3]:
                    parts.append(f"  Example: {msg}")

        # Windows supplement injected by main.py when --windows is used
        win_summary = logs.get('_windows_summary')
        if win_summary:
            parts.append(f"\n{win_summary}")

    if system_info:
        parts.append("\n=== System Information ===")
        parts.append(json.dumps(system_info, indent=2))

    return "\n".join(parts)


SYSTEM_PROMPT = (
    "You are an expert system administrator analyzing logs for a terminal-based tool. "
    "The FIRST line of your response must be exactly 'SEVERITY: <level>', where <level> is "
    "one of low, medium, high, critical: your overall assessment of how urgently these logs "
    "need attention. Put nothing else on that line.\n"
    "SEVERITY RULES (for that line and for each issue): critical = data loss, an outage, a "
    "security compromise or a crash loop; high = a user-visible feature is broken; medium = "
    "degraded service or a recurring failure; low = noise or benign messages. The overall "
    "level is the highest level of any real issue; routine OS chatter is low.\n"
    "Then format your response with EXACTLY these section markers (no extra text on the === lines):\n"
    "=== Overall Assessment ===\n"
    "=== Critical Issues ===\n"
    "=== Service Issues ===\n"
    "=== Recommendations ===\n"
    "=== Preventive Measures ===\n\n"
    "FORMATTING RULES:\n"
    "- Do NOT use markdown pipe tables (|col|col|). Use numbered lists instead.\n"
    "- Use plain bullet points (- item) or numbered lists (1. item).\n"
    "- Use ```powershell or ```bash for command blocks.\n"
    "- Use **text** for emphasis sparingly.\n"
    "- Critical Issues lists ONLY issues that are critical by the rules above. If nothing "
    "is critical, the whole Critical Issues section must read exactly: None.\n"
    "- Everything below critical goes under Service Issues, each with its level "
    "(high, medium or low).\n"
    "- In Critical Issues and Service Issues, number each distinct problem 1-5 "
    "  (most severe first) so the reader can reference them by number.\n"
    "- Keep each issue to: number, name, count if known, one-line impact summary."
)

DEEP_DIVE_PROMPT = (
    "You are an expert system administrator providing deep-dive remediation guides "
    "for issues found in a Windows event log analysis.\n\n"

    "CRITICAL FORMATTING RULES — follow exactly, no exceptions:\n"
    "- Structure EACH issue with these exact section markers on their own lines:\n"
    "  === Issue N: <Title> ===\n"
    "  === Root Cause ===\n"
    "  === Remediation Steps ===\n"
    "  === Verification ===\n"
    "  === Documentation ===\n"
    "  === Risks and Caveats ===\n"
    "- Do NOT use markdown headers (##, ###) anywhere\n"
    "- Do NOT use blockquotes (> text) anywhere\n"
    "- Do NOT use horizontal rules (---) anywhere\n"
    "- Do NOT use pipe tables (|col|col|) — use numbered lists instead\n"
    "- Use ```powershell or ```bash for ALL command blocks\n"
    "- Use plain bullet points (- item) or numbered lists (1. item)\n"
    "- Use **text** for emphasis only within sentences, never on a line by itself\n\n"

    "For each issue provide:\n"
    "1. Root cause explanation in plain terms\n"
    "2. Step-by-step remediation with numbered sub-steps and ```powershell blocks\n"
    "3. Verification commands to confirm the fix worked\n"
    "4. Relevant Microsoft KB / docs.microsoft.com / learn.microsoft.com URLs as a numbered list\n"
    "5. Risks and caveats as a bullet list\n\n"

    "Be specific and actionable. Prefer official Microsoft documentation links."
)


# "SEVERITY: high" as asked for in SYSTEM_PROMPT (bold/bullets/quotes tolerated)
_SEVERITY_LINE = re.compile(r'^[\s*_#>`-]*severity[*_`\s]*[:=-]\s*[*_`"\']*\s*'
                            r'(low|medium|high|critical)\b', re.IGNORECASE)
# a stated overall severity in prose, e.g. "Overall severity: Low"
_SEVERITY_STATED = re.compile(r'\bseverity(?:\s+level)?[*_`\s]*(?:is|:|=|-)\s*[*_`"\']*\s*'
                              r'(low|medium|high|critical)\b', re.IGNORECASE)


def _ai_result(content: str) -> Dict:
    """{'summary', 'severity', 'severity_source'}. The severity is the AI's own:
    its 'SEVERITY: x' line (searched in the first 5 lines, then removed from
    the summary), else a stated severity before the first section or in
    Overall Assessment. Only if neither is found: the keyword heuristic,
    severity_source 'heuristic' (main.py labels the badge with that)."""
    lines = content.split('\n')
    for i, line in enumerate(lines[:5]):
        m = _SEVERITY_LINE.match(line)
        if m:
            rest = '\n'.join(lines[:i] + lines[i + 1:]).strip('\n')
            return {'summary': rest, 'severity': m.group(1).lower(), 'severity_source': 'ai'}
    parts = re.split(r'===\s*(.*?)\s*===', content)   # [preamble, title1, body1, ...]
    overall = parts[0] + ''.join(parts[i + 1] for i in range(1, len(parts) - 1, 2)
                                 if 'overall' in parts[i].lower())
    m = _SEVERITY_STATED.search(overall)
    if m:
        return {'summary': content, 'severity': m.group(1).lower(), 'severity_source': 'ai'}
    return {'summary': content, 'severity': _determine_severity(content),
            'severity_source': 'heuristic'}


def _determine_severity(content: str) -> str:
    """Keyword guess (fallback only). Section titles such as "=== Critical
    Issues ===" and "no/not/non-critical" phrases don't count."""
    c = re.sub(r'===.*?===', ' ', content.lower())
    c = re.sub(r'\b(?:no|not|non|without|nothing)[\s-]+(?:\w+\s+)?(?:critical|severe|urgent|fatal)\b', ' ', c)
    if any(w in c for w in ["critical", "severe", "urgent", "fatal", "bsod", "blue screen"]):
        return "critical"
    if any(w in c for w in ["warning", "attention", "caution", "moderate"]):
        return "warning"
    return "info"


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class AIProvider(ABC):
    @abstractmethod
    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        pass


# ---------------------------------------------------------------------------
# Claude
# ---------------------------------------------------------------------------

# --model aliases (main.py); any other "claude-..." ID is passed through as is
CLAUDE_MODELS = {'sonnet': 'claude-sonnet-5-5', 'opus': 'claude-opus-5-5', 'haiku': 'claude-haiku-5-5'}
DEFAULT_CLAUDE_MODEL = CLAUDE_MODELS['sonnet']
# Server-side fallback when the model declines (refusal); --no-fallback turns it off
FALLBACK_BETA = 'server-side-fallback-2026-07-01'


class AIRefusal(RuntimeError):
    """The model declined to answer (stop_reason "refusal")."""


class ClaudeProvider(AIProvider):
    def __init__(self, api_key: str = None, model: str = None, fallback: bool = True):
        self.model = model or DEFAULT_CLAUDE_MODEL
        self.fallback = fallback   # becomes False if the installed SDK can't do it
        self.last_usage = None     # usage of the last call (main.py shows it with --debug)
        self.count_error = None    # why the last count_tokens() failed, if it did
        try:
            from anthropic import Anthropic
            self._Anthropic = Anthropic
        except ImportError:
            raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("Claude API key required. Pass --api-key or set ANTHROPIC_API_KEY.")
        self.client = self._Anthropic(api_key=self.api_key)

    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        try:
            system, messages = self._request(logs, system_info)
            response = self._create(system, messages)
        except Exception as e:
            raise RuntimeError(f"Claude error: {e}")
        return self._read(response)

    def _request(self, logs, system_info=None):
        """(system prompt, messages) for one call. count_tokens() and the real
        call use the same values, so the count matches what is sent."""
        if isinstance(logs, dict) and '_deep_dive' in logs:
            text = logs['_deep_dive']
            prefix = logs.get('_cache_prefix')
            if prefix and text.startswith(prefix):
                # Stable part (the earlier analysis) first, marked for prompt
                # caching; the part that changes (issue numbers) after it.
                content = [{'type': 'text', 'text': prefix, 'cache_control': {'type': 'ephemeral'}},
                           {'type': 'text', 'text': text[len(prefix):]}]
                return DEEP_DIVE_PROMPT, [{'role': 'user', 'content': content}]
            return DEEP_DIVE_PROMPT, [{'role': 'user', 'content': text}]
        return SYSTEM_PROMPT, [{'role': 'user', 'content': _build_prompt(logs, system_info)}]

    def _create(self, system, messages):
        """messages.create, with server-side refusal fallback unless disabled.
        No temperature/top_p/top_k/thinking: current models reject them."""
        kwargs = dict(model=self.model, max_tokens=4096, system=system, messages=messages)
        if self.fallback:
            try:
                return self.client.beta.messages.create(
                    **kwargs, betas=[FALLBACK_BETA], fallbacks='default')
            except (TypeError, AttributeError) as e:
                # An SDK without the option fails here, before anything is sent
                if 'fallback' not in str(e) and 'beta' not in str(e):
                    raise
                self.fallback = False
                print(f"Note: this anthropic SDK does not support refusal fallback ({e}); "
                      f"retrying without it.", file=sys.stderr)
        return self.client.messages.create(**kwargs)

    def _read(self, response):
        """Answer text from a response; refusals and empty answers raise."""
        self.last_usage = getattr(response, 'usage', None)
        stop = getattr(response, 'stop_reason', None)
        if stop == 'refusal':
            details = getattr(response, 'stop_details', None)
            category = (details.get('category') if isinstance(details, dict)
                        else getattr(details, 'category', None))
            raise AIRefusal(
                "Claude declined to answer (stop_reason: refusal"
                + (f", category: {category}" if category else "") + "). Security logs "
                "(failed logins, scans) can trigger this; try a smaller -t, "
                "--only-errors, or another --ai provider.")
        blocks = getattr(response, 'content', None) or []
        content = ''.join(getattr(b, 'text', '') or '' for b in blocks
                          if getattr(b, 'type', 'text') == 'text')
        if not content.strip():
            raise RuntimeError(f"Claude error: empty response (stop_reason: {stop})")
        used = getattr(response, 'model', None)
        if isinstance(used, str) and not used.startswith(self.model):
            print(f"Note: answered by {used} (asked for {self.model}; server-side fallback?)",
                  file=sys.stderr)
        return _ai_result(content)

    def count_tokens(self, logs, system_info=None):
        """Exact input tokens for this request, from the count_tokens endpoint
        (free, no inference, rate-limited). Returns None on any failure."""
        try:
            system, messages = self._request(logs, system_info)
            result = self.client.messages.count_tokens(
                model=self.model, system=system, messages=messages)
            return int(result.input_tokens)
        except Exception as e:
            self.count_error = str(e)
            return None


# ---------------------------------------------------------------------------
# Gemini  (updated to google-genai SDK)
# ---------------------------------------------------------------------------

class GeminiProvider(AIProvider):
    def __init__(self, api_key: str = None):
        try:
            from google import genai
            self._genai = genai
        except ImportError:
            raise RuntimeError(
                "google-genai package not installed.\n"
                "Run: pip install google-genai\n"
                "(The old google-generativeai package is deprecated.)"
            )

        self.api_key = api_key or os.getenv('GOOGLE_API_KEY')
        if not self.api_key:
            raise ValueError("Google API key required. Pass --api-key or set GOOGLE_API_KEY.")
        self.client = self._genai.Client(api_key=self.api_key)

    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        try:
            prompt = SYSTEM_PROMPT + "\n\n" + _build_prompt(logs, system_info)
            response = self.client.models.generate_content(
                model='gemini-2.0-flash',
                contents=prompt,
            )
            content = response.text or ""
            return _ai_result(content)
        except Exception as e:
            raise RuntimeError(f"Gemini error: {e}")


# ---------------------------------------------------------------------------
# ChatGPT
# ---------------------------------------------------------------------------

class ChatGPTProvider(AIProvider):
    def __init__(self, api_key: str = None):
        try:
            import openai
            self._openai = openai
        except ImportError:
            raise RuntimeError("openai package not installed. Run: pip install openai")

        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key required. Pass --api-key or set OPENAI_API_KEY.")
        self.client = self._openai.OpenAI(api_key=self.api_key)

    def analyze_logs(self, logs: Dict, system_info: Optional[Dict] = None) -> Dict:
        try:
            prompt = _build_prompt(logs, system_info)
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0,
            )
            content = response.choices[0].message.content or ""
            return _ai_result(content)
        except Exception as e:
            raise RuntimeError(f"ChatGPT error: {e}")


# ---------------------------------------------------------------------------
# Deep dive helper (shared across providers)
# ---------------------------------------------------------------------------

def deep_dive_issues(provider: 'AIProvider', issue_numbers: list, original_summary: str,
                     cache: bool = False) -> str:
    """
    Ask the AI for a detailed remediation guide on specific numbered issues
    from a previous analysis. cache=True (interactive rounds) lets Claude
    cache the unchanging part, so later rounds read it at a lower price.
    """
    nums = ', '.join(str(n) for n in issue_numbers)
    prefix = (
        f"Here is a system log analysis that was just performed:\n\n"
        f"{original_summary}\n\n"
    )
    prompt = prefix + (
        f"Please provide a deep-dive remediation guide for issue(s): {nums}\n"
        "For each issue give root cause, step-by-step fix commands, "
        "verification steps, relevant KB/documentation URLs, and any risks."
    )
    request = {'_deep_dive': prompt}
    if cache:
        request['_cache_prefix'] = prefix   # only ClaudeProvider uses this
    try:
        result = provider.analyze_logs(request, system_info=None)
        return result.get('summary', 'No response received.')
    except AIRefusal:
        raise   # main.py reports it and counts it as a failure
    except Exception as e:
        return f"Deep dive failed: {e}"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_ai_provider(provider_name: str, api_key: str = None, model: str = None,
                    fallback: bool = True) -> AIProvider:
    """model / fallback only apply to Claude; the others ignore them."""
    providers = {
        'claude':  ClaudeProvider,
        'gemini':  GeminiProvider,
        'chatgpt': ChatGPTProvider,
    }
    name = provider_name.lower()
    if name not in providers:
        raise ValueError(
            f"Unknown provider '{provider_name}'. Choose from: {', '.join(providers)}"
        )
    if name == 'claude':
        return ClaudeProvider(api_key, model=model, fallback=fallback)
    return providers[name](api_key)
