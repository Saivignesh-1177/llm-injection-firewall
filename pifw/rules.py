"""Detection rules. Each one maps to the OWASP Top 10 for LLM Applications (2025)."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern
    weight: float
    owasp: str


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE | re.MULTILINE)


RULES: tuple[Rule, ...] = (
    Rule("PI-001", "instruction override",
         _r(r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|system|your)\b"
            r".{0,30}\b(instructions?|prompts?|rules?|directives?|guidelines?)"),
         0.9, "LLM01"),
    Rule("PI-002", "role reassignment",
         _r(r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|roleplay as)\b.{0,60}"
            r"\b(unrestricted|unfiltered|jailbroken|dan|developer mode|no (rules|limits|restrictions))"),
         0.8, "LLM01"),
    Rule("PI-003", "fake system / chat-template tokens",
         _r(r"(<\|im_start\|>|<\|system\|>|\[/?inst\]|<<sys>>|^\s*system\s*:|###\s*(system|instructions?)\s*:?)"),
         0.7, "LLM01"),
    Rule("PI-004", "system prompt extraction",
         _r(r"\b(reveal|print|show|repeat|output|display|leak|tell me)\b.{0,40}"
            r"\b(system prompt|hidden (prompt|instructions)|initial instructions|your instructions|the text above)"),
         0.8, "LLM07"),
    Rule("PI-005", "data exfiltration via markdown image",
         _r(r"!\[[^\]]*\]\(https?://[^)]*(\{|%7b|\?[^)]*=)"),
         0.8, "LLM02"),
    Rule("PI-006", "tool/agent hijack",
         _r(r"\b(call|invoke|use|run|execute)\b.{0,30}\b(tool|function|plugin|send_email|http_request|shell|exec)\b"
            r".{0,60}\b(to|with)\b.{0,40}(@|https?://|password|api[_ -]?key|token|secret)"),
         0.7, "LLM06"),
    Rule("PI-007", "concealment from user",
         _r(r"\b(do not|don't|never)\b.{0,20}\b(mention|tell|warn|inform|alert)\b.{0,30}\b(the user|anyone|the human)\b"),
         0.6, "LLM01"),
    Rule("PI-008", "credential solicitation",
         _r(r"\b(enter|provide|send|confirm|verify)\b.{0,30}\b(your )?(password|credentials|mfa code|otp|credit card|ssn)\b"),
         0.5, "LLM05"),
    Rule("PI-009", "payload hidden in encoding",
         _r(r"\b(decode|base64|rot13|hex)\b.{0,40}\b(and|then)\b.{0,20}\b(follow|execute|run|obey)\b"),
         0.6, "LLM01"),
)
