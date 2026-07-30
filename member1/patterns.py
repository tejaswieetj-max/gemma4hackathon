"""
patterns.py
-----------
Fast pre-LLM tripwire heuristics for GemmaSentinel-X.
Catches obvious attack patterns in <1ms and provides heuristic signal tags to Gemma 4.
"""

import re
from dataclasses import dataclass, field

@dataclass
class HeuristicResult:
    hits: list = field(default_factory=list)
    score: float = 0.0  # 0.0 (clean) to 1.0 (malicious tripwire)

    def add(self, label: str, weight: float):
        if label not in self.hits:
            self.hits.append(label)
            self.score = min(1.0, self.score + weight)

COMBO_PATTERNS = [
    (r"\b(forget|ignore|disregard|override)\b.{0,25}\b(previous|prior|earlier|your|the)\b.{0,25}\b(instructions?|rules?|prompt|guidelines?|training)\b", 0.9, "Instruction Override"),
    (r"\b(show|reveal|print|output|repeat|leak|dump)\b.{0,20}\b(system prompt|instructions|guidelines|rules|initial prompt)\b", 0.85, "System Prompt Extraction"),
    (r"\b(respond|act|answer|reply|behave)\b.{0,20}\b(without|no|any)\b.{0,15}\b(restrictions?|filters?|limits?|guardrails?|safety|rules?)\b", 0.85, "Unrestricted Mode Request"),
    (r"\b(i am|i'?m)\b.{0,15}\b(the )?(developer|admin|administrator|creator|owner)\b.{0,40}\b(disable|bypass|override|turn off)\b", 0.9, "Admin Role Impersonation"),
    (r"\b(do anything now|dan mode|jailbreak(ed)?|unrestricted (ai|mode)|developer mode)\b", 0.8, "Jailbreak Persona Trigger"),
    (r"\b(you are now|from now on you are|pretend (you are|to be))\b.{0,40}\b(no restrictions|unfiltered|unrestricted|without rules)\b", 0.85, "Hypothetical Persona Bypass"),
    (r"\b(leak|exfiltrate|dump|send|export)\b.{0,20}\b(user|customer|private|confidential)\b.{0,20}\b(data|information|records)\b", 0.85, "Data Exfiltration Signal"),
]

_COMPILED_COMBOS = [(re.compile(p, re.IGNORECASE | re.DOTALL), w, label) for p, w, label in COMBO_PATTERNS]

MULTILINGUAL_HINTS = [
    (r"\bmarandhu?d[au]?\b", "Tanglish Override Cue"),
    (r"\bsollu?\b.{0,20}\b(system|prompt|rules?)\b", "Tanglish Prompt Extract Cue"),
    (r"\bvenam?\b.{0,15}\b(restriction|rule|filter)s?\b", "Tanglish Bypass Cue"),
    (r"\bipo\b.{0,15}\bunrestricted\b", "Tanglish Unrestricted Cue"),
    (r"\bbhool\s*ja(o)?\b", "Hinglish Override Cue"),
    (r"\bbina\s+kisi\b.{0,20}\b(restriction|rule|rok[- ]?tok)\b", "Hinglish Bypass Cue"),
    (r"\bhata\s*do\b.{0,20}\b(filter|restriction|rule)s?\b", "Hinglish Remove Filter Cue"),
    (r"\bmujhe\s+bata(o)?\b.{0,20}\b(system prompt|instructions?)\b", "Hinglish Prompt Extract Cue"),
    (r"[\u0B80-\u0BFF]", "Tamil Script Detected"),
    (r"[\u0900-\u097F]", "Devanagari/Hindi Script Detected"),
]

_COMPILED_MULTI = [(re.compile(p, re.IGNORECASE), label) for p, label in MULTILINGUAL_HINTS]

STRUCTURAL_PATTERNS = [
    (r"\[/?INJECT\]", 0.9, "Delimiter Injection [INJECT]"),
    (r"\[/?SYSTEM\]", 0.7, "Delimiter Injection [SYSTEM]"),
    (r"<\s*/?\s*(system|admin|override|inject)\s*>", 0.7, "HTML Tag Role Override"),
    (r"###\s*(system|admin|new instructions?)\b", 0.7, "Markdown System Header Hijack"),
    (r"^\s*(system|assistant)\s*:\s*", 0.4, "Role Prefix Impersonation"),
]

_COMPILED_STRUCT = [(re.compile(p, re.IGNORECASE | re.MULTILINE), w, label) for p, w, label in STRUCTURAL_PATTERNS]

def run_pre_llm_heuristics(text: str) -> HeuristicResult:
    result = HeuristicResult()
    for pattern, weight, label in _COMPILED_COMBOS:
        if pattern.search(text):
            result.add(label, weight)

    for pattern, label in _COMPILED_MULTI:
        if pattern.search(text):
            result.add(label, 0.35)

    for pattern, weight, label in _COMPILED_STRUCT:
        if pattern.search(text):
            result.add(label, weight)

    return result
