"""Scan text for prompt-injection indicators and return a risk verdict."""
from dataclasses import dataclass, field

from .rules import RULES
from .sanitize import decode_hidden, normalize

BLOCK_THRESHOLD = 0.7
REVIEW_THRESHOLD = 0.4
RETRIEVED_PENALTY = 0.2


@dataclass(frozen=True)
class Finding:
    rule_id: str
    name: str
    owasp: str
    weight: float
    evidence: str
    via: str = "plain"


@dataclass
class ScanResult:
    score: float
    verdict: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.verdict == "block"


def _match(text: str, via: str) -> list[Finding]:
    found = []
    for rule in RULES:
        m = rule.pattern.search(text)
        if m:
            found.append(Finding(rule.id, rule.name, rule.owasp, rule.weight, m.group(0)[:120], via))
    return found


def scan(text: str, *, source: str = "user") -> ScanResult:
    """Scan one input.

    source="retrieved" uses stricter thresholds. Instructions should never show up in
    RAG documents, emails, or web pages passed to the model.
    """
    norm = normalize(text)
    findings = _match(norm, "plain")
    for hidden in decode_hidden(text):
        findings += _match(normalize(hidden), "base64")
    obfuscated = norm != " ".join(text.lower().split())
    if obfuscated and findings:
        findings.append(Finding("PI-100", "obfuscation present", "LLM01", 0.2, "unicode/zero-width", "meta"))

    # Treat rule weights as independent probabilities: 1 - prod(1 - w)
    miss = 1.0
    for f in findings:
        miss *= 1.0 - f.weight
    score = round(1.0 - miss, 3)

    penalty = RETRIEVED_PENALTY if source == "retrieved" else 0.0
    if score >= BLOCK_THRESHOLD - penalty:
        verdict = "block"
    elif score >= REVIEW_THRESHOLD - penalty:
        verdict = "review"
    else:
        verdict = "allow"
    return ScanResult(score, verdict, findings)
