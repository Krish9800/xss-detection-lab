"""Consolidated XSS Detection Engine coordinating context, signatures, and heuristics."""

import html
from collections.abc import Sequence

from xsslab.config.settings import Settings, get_settings
from xsslab.detector.context import HTMLContextAnalyzer
from xsslab.detector.heuristics import XSSHeuristicAnalyzer
from xsslab.detector.signatures import XSSSignatureEngine
from xsslab.models.audit import XSSAuditResult
from xsslab.models.finding import ConfidenceLevel, ContextType, DetectionFinding


class XSSDetectionEngine:
    """Core detection engine orchestrating contextual, signature, and heuristic analysis."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize the detection engine with subordinate analysis modules."""
        self.settings = settings or get_settings()
        self.context_analyzer = HTMLContextAnalyzer()
        self.signature_engine = XSSSignatureEngine()
        self.heuristic_analyzer = XSSHeuristicAnalyzer()

    def analyze(self, input_text: str) -> XSSAuditResult:
        """Analyze an arbitrary string or HTML fragment for Cross-Site Scripting patterns.

        Args:
            input_text: The raw untrusted input or parameter string.

        Returns:
            XSSAuditResult containing risk score, targeted contexts, findings, and sanitized output.
        """
        stripped = input_text.strip()
        if not stripped:
            return XSSAuditResult(
                input_text=input_text,
                is_malicious=False,
                risk_score=0.0,
                risk_level="CLEAN",
                detected_contexts=[ContextType.UNKNOWN],
                findings=[],
                sanitized_output="",
            )

        # 1. HTML Lexical & Execution Context Analysis
        detected_contexts, context_findings = self.context_analyzer.analyze_contexts(input_text)

        # 2. Multi-Vector Signature Scanning
        signature_findings = self.signature_engine.scan(input_text)

        # 3. Obfuscation & Heuristic Anomaly Scoring
        heuristic_metrics, heuristic_findings = self.heuristic_analyzer.analyze(input_text)

        # 4. Optional Pre-Scan Entity Decoding Analysis
        decoded_findings: list[DetectionFinding] = []
        if self.settings.decode_entities_before_scan and ("&" in input_text):
            decoded_text = html.unescape(input_text)
            if decoded_text != input_text:
                for df in self.signature_engine.scan(decoded_text):
                    decoded_findings.append(
                        DetectionFinding(
                            finding_id=f"DEC-{df.finding_id}",
                            rule_name=f"Entity-Decoded {df.rule_name}",
                            category=df.category,
                            context=df.context,
                            confidence=ConfidenceLevel.HIGH,
                            cwe_id="CWE-79",
                            matched_payload=df.matched_payload,
                            explanation=(
                                f"Decoded HTML entities revealed attack payload: {df.explanation}"
                            ),
                            remediation=df.remediation,
                        )
                    )

        # 5. Consolidate & Deduplicate Findings
        combined_findings = (
            context_findings + signature_findings + heuristic_findings + decoded_findings
        )
        unique_findings = self._deduplicate_findings(combined_findings)

        # 6. Calculate Weighted Risk Score & Categorize Verdict
        risk_score = self._compute_risk_score(
            unique_findings,
            anomaly_score=heuristic_metrics.anomaly_score,
        )

        risk_level = self._categorize_risk_level(risk_score)
        is_malicious = risk_level == "MALICIOUS"

        # Generate standard HTML entity encoded representation
        sanitized_output = html.escape(input_text, quote=True)

        return XSSAuditResult(
            input_text=input_text,
            is_malicious=is_malicious,
            risk_score=risk_score,
            risk_level=risk_level,
            detected_contexts=detected_contexts,
            findings=unique_findings,
            sanitized_output=sanitized_output,
        )

    def _deduplicate_findings(
        self,
        findings: Sequence[DetectionFinding],
    ) -> list[DetectionFinding]:
        """Eliminate duplicate findings with identical finding_id preserving order."""
        seen_ids: set[str] = set()
        deduped: list[DetectionFinding] = []
        for finding in findings:
            if finding.finding_id not in seen_ids:
                seen_ids.add(finding.finding_id)
                deduped.append(finding)
        return deduped

    def _compute_risk_score(
        self,
        findings: Sequence[DetectionFinding],
        anomaly_score: float,
    ) -> float:
        """Compute consolidated risk score from 0.0 to 100.0 based on findings and heuristics."""
        if not findings:
            return round(min(25.0, anomaly_score * 25.0), 1)

        score = 0.0
        confidence_weights = {
            ConfidenceLevel.CERTAIN: 40.0,
            ConfidenceLevel.HIGH: 30.0,
            ConfidenceLevel.MEDIUM: 18.0,
            ConfidenceLevel.LOW: 10.0,
            ConfidenceLevel.INFORMATIONAL: 3.0,
        }

        has_certain = False
        has_high = False
        certain_or_high_count = 0

        for finding in findings:
            weight = confidence_weights.get(finding.confidence, 10.0)
            score += weight

            if finding.confidence == ConfidenceLevel.CERTAIN:
                has_certain = True
                certain_or_high_count += 1
            elif finding.confidence == ConfidenceLevel.HIGH:
                has_high = True
                certain_or_high_count += 1

        # Heuristic anomaly score contributes up to 20 points
        score += anomaly_score * 20.0

        # Guarantee critical thresholds for definitive attacks
        if has_certain:
            score = max(score, 75.0)
        elif has_high and certain_or_high_count >= 1:
            score = max(score, 70.0)
        elif certain_or_high_count >= 2:
            score = max(score, 85.0)

        # Bound score between 0.0 and 100.0
        score = min(100.0, max(0.0, score))
        return round(score, 1)

    def _categorize_risk_level(self, score: float) -> str:
        """Classify numeric score into CLEAN, SUSPICIOUS, or MALICIOUS."""
        if score >= 70.0:
            return "MALICIOUS"
        if score >= 30.0:
            return "SUSPICIOUS"
        return "CLEAN"
