"""Heuristic and obfuscation analysis engine for detecting evasion techniques in XSS payloads."""

import math
import re
from dataclasses import dataclass
from typing import ClassVar

from xsslab.models.finding import (
    ConfidenceLevel,
    ContextType,
    DetectionFinding,
    XSSCategory,
)


@dataclass(frozen=True)
class XSSHeuristicMetrics:
    """Statistical and obfuscation metrics for an inspected input string."""

    entropy: float
    special_char_density: float
    entity_count: int
    has_mixed_case_tags: bool
    anomaly_score: float


class XSSHeuristicAnalyzer:
    """Detects encoding evasion, obfuscated entities, and structural anomalies."""

    SPECIAL_CHARS: ClassVar[set[str]] = {
        "<",
        ">",
        '"',
        "'",
        "/",
        "\\",
        "&",
        "#",
        ";",
        "(",
        ")",
        "=",
        ":",
        "`",
        "+",
        "%",
    }

    # Patterns for encoded entity bypasses
    HEX_ENTITY_PATTERN = re.compile(r"&#x[0-9a-fA-F]+;?", re.IGNORECASE)
    DEC_ENTITY_PATTERN = re.compile(r"&#\d+;?")
    NAMED_BYPASS_PATTERN = re.compile(
        r"&(colon|tab|newline|lpar|rpar|grave);?",
        re.IGNORECASE,
    )
    JS_UNICODE_HEX_PATTERN = re.compile(r"\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})")
    FROM_CHARCODE_PATTERN = re.compile(
        r"(?i)\b(string\s*\.\s*fromcharcode|atob)\s*\(",
    )
    MIXED_CASE_TAG_PATTERN = re.compile(
        r"<(?![A-Z]{2,}|[a-z]{2,})([A-Za-z]{2,10})[\s>/]",
    )

    @classmethod
    def calculate_shannon_entropy(cls, text: str) -> float:
        """Calculate Shannon information entropy (H) in bits per character."""
        if not text:
            return 0.0
        frequencies: dict[str, int] = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def calculate_special_char_density(cls, text: str) -> float:
        """Calculate the proportion of HTML/JS delimiter characters."""
        if not text:
            return 0.0
        special_count = sum(1 for c in text if c in cls.SPECIAL_CHARS)
        return round(special_count / len(text), 4)

    @classmethod
    def analyze_heuristics(
        cls,
        text: str,
    ) -> tuple[XSSHeuristicMetrics, list[DetectionFinding]]:
        """Evaluate obfuscation indicators and produce findings and metrics.

        Args:
            text: The raw untrusted input string.

        Returns:
            Tuple of (XSSHeuristicMetrics, list of DetectionFinding).
        """
        findings: list[DetectionFinding] = []
        if not text or not text.strip():
            metrics = XSSHeuristicMetrics(
                entropy=0.0,
                special_char_density=0.0,
                entity_count=0,
                has_mixed_case_tags=False,
                anomaly_score=0.0,
            )
            return metrics, findings

        clean = text.strip()
        entropy = cls.calculate_shannon_entropy(clean)
        special_density = cls.calculate_special_char_density(clean)

        # 1. HTML Entity Obfuscation
        hex_entities = cls.HEX_ENTITY_PATTERN.findall(clean)
        dec_entities = cls.DEC_ENTITY_PATTERN.findall(clean)
        named_entities = cls.NAMED_BYPASS_PATTERN.findall(clean)
        total_entities = len(hex_entities) + len(dec_entities) + len(named_entities)

        if total_entities > 0:
            findings.append(
                DetectionFinding(
                    finding_id="HEUR-XSS-ENTITY-01",
                    rule_name="HTML Numeric / Named Entity Evasion",
                    category=XSSCategory.HEURISTIC_ANOMALY,
                    context=ContextType.HTML_BODY,
                    confidence=ConfidenceLevel.HIGH,
                    matched_payload=f"{total_entities} entities detected",
                    explanation=(
                        f"Detected {total_entities} HTML entities (hex, decimal, or named) "
                        "commonly used to obfuscate tag delimiters and event handlers."
                    ),
                    remediation="Decode input recursively and apply strict context encoding.",
                    details={
                        "hex_count": len(hex_entities),
                        "dec_count": len(dec_entities),
                        "named_count": len(named_entities),
                    },
                )
            )

        # 2. JavaScript Unicode and Hex Escape Sequences
        js_escapes = cls.JS_UNICODE_HEX_PATTERN.findall(clean)
        if len(js_escapes) >= 2:
            findings.append(
                DetectionFinding(
                    finding_id="HEUR-XSS-JS-ESCAPE-01",
                    rule_name="JavaScript Unicode/Hex Escape Sequences",
                    category=XSSCategory.HEURISTIC_ANOMALY,
                    context=ContextType.JAVASCRIPT,
                    confidence=ConfidenceLevel.HIGH,
                    matched_payload=clean[:50],
                    explanation=(
                        f"Detected {len(js_escapes)} JavaScript Unicode/hex escape sequences "
                        "used to hide malicious strings and API calls."
                    ),
                )
            )

        # 3. Dynamic Decoders & String Generators (fromCharCode, atob)
        charcode_match = cls.FROM_CHARCODE_PATTERN.search(clean)
        if charcode_match:
            findings.append(
                DetectionFinding(
                    finding_id="HEUR-XSS-CHARCODE-01",
                    rule_name="Dynamic String Generation (fromCharCode / atob)",
                    category=XSSCategory.SCRIPT_GADGET,
                    context=ContextType.JAVASCRIPT,
                    confidence=ConfidenceLevel.HIGH,
                    matched_payload=charcode_match.group(0),
                    explanation=(
                        f"Detected dynamic string construction via '{charcode_match.group(0)}' "
                        "bypassing character-based string filters."
                    ),
                )
            )

        # 4. Mixed-Case Tag Permutations (e.g. <sCrIpt>, <SvG>)
        has_mixed_case = bool(cls.MIXED_CASE_TAG_PATTERN.search(clean))
        if has_mixed_case and ("<" in clean and ">" in clean):
            findings.append(
                DetectionFinding(
                    finding_id="HEUR-XSS-MIXEDCASE-01",
                    rule_name="Mixed-Case Tag WAF Filter Bypass",
                    category=XSSCategory.HEURISTIC_ANOMALY,
                    context=ContextType.HTML_BODY,
                    confidence=ConfidenceLevel.MEDIUM,
                    matched_payload=clean[:40],
                    explanation=(
                        "Detected mixed-case HTML tag naming designed to evade case-sensitive "
                        "regular expression filters."
                    ),
                )
            )

        # Calculate composite anomaly score (0.0 to 1.0)
        anomaly = 0.0
        anomaly += min(0.4, special_density * 1.2)
        anomaly += min(0.3, total_entities * 0.1)
        if js_escapes:
            anomaly += 0.2
        if charcode_match:
            anomaly += 0.25
        if has_mixed_case:
            anomaly += 0.15

        anomaly_score = min(1.0, round(anomaly, 3))

        metrics = XSSHeuristicMetrics(
            entropy=entropy,
            special_char_density=special_density,
            entity_count=total_entities,
            has_mixed_case_tags=has_mixed_case,
            anomaly_score=anomaly_score,
        )
        return metrics, findings

    def analyze(
        self,
        text: str,
    ) -> tuple[XSSHeuristicMetrics, list[DetectionFinding]]:
        """Instance method alias for analyze_heuristics."""
        return self.analyze_heuristics(text)
