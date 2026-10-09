"""Multi-vector XSS signature scanning engine."""

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
class XSSSignatureRule:
    """Definition of an individual XSS signature detection rule."""

    rule_id: str
    name: str
    category: XSSCategory
    context: ContextType
    confidence: ConfidenceLevel
    pattern: re.Pattern[str]
    explanation: str
    remediation: str = (
        "Apply context-appropriate output encoding and strict Content Security Policy."
    )


class XSSSignatureEngine:
    """Evaluates untrusted inputs against curated multi-vector regular expression rules."""

    RULES: ClassVar[list[XSSSignatureRule]] = [
        # 1. Dangerous Executable HTML Elements
        XSSSignatureRule(
            rule_id="SIG-XSS-TAG-SCRIPT",
            name="Inline Script Tag Injection",
            category=XSSCategory.HTML_TAG_INJECTION,
            context=ContextType.HTML_BODY,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)<\s*script\b[^>]*>", re.DOTALL),
            explanation="Detected inline <script> tag used to execute arbitrary client-side code.",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-TAG-IFRAME",
            name="Arbitrary Frame Embed Injection",
            category=XSSCategory.HTML_TAG_INJECTION,
            context=ContextType.HTML_BODY,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(r"(?i)<\s*iframe\b[^>]*>", re.DOTALL),
            explanation="Detected <iframe> element which can load external or javascript: content.",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-TAG-SVG",
            name="SVG Vector Element Injection",
            category=XSSCategory.HTML_TAG_INJECTION,
            context=ContextType.HTML_BODY,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(r"(?i)<\s*svg\b[^>]*>", re.DOTALL),
            explanation="Detected <svg> element frequently leveraged for XML/SVG inline script triggers.",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-TAG-OBJECT",
            name="Object/Embed Plugin Tag Injection",
            category=XSSCategory.HTML_TAG_INJECTION,
            context=ContextType.HTML_BODY,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(r"(?i)<\s*(object|embed|applet)\b[^>]*>", re.DOTALL),
            explanation="Detected plugin embedding element capable of loading hostile active content.",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-TAG-BASE",
            name="Base Tag Origin Hijacking",
            category=XSSCategory.HTML_TAG_INJECTION,
            context=ContextType.HTML_BODY,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)<\s*base\b[^>]*href\s*=", re.DOTALL),
            explanation="Detected <base> tag manipulation targeting relative script URL resolution.",
        ),
        # 2. Inline Event Handlers
        XSSSignatureRule(
            rule_id="SIG-XSS-EVENT-LOAD",
            name="Automatic Execution Event Handler",
            category=XSSCategory.EVENT_HANDLER,
            context=ContextType.ATTRIBUTE,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(
                r"(?i)\b(onload|onerror|onpageshow|onanimationstart)\s*=",
            ),
            explanation="Detected automatic execution event handler (e.g. onload, onerror).",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-EVENT-USER",
            name="User Interaction Event Handler",
            category=XSSCategory.EVENT_HANDLER,
            context=ContextType.ATTRIBUTE,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(
                r"(?i)\b(onclick|onmouseover|onmouseenter|onfocus|onblur|onkeydown)\s*=",
            ),
            explanation="Detected user interaction event handler capable of executing injected script.",
        ),
        # 3. Pseudo-Protocols & Data URIs
        XSSSignatureRule(
            rule_id="SIG-XSS-PROTO-JS",
            name="JavaScript Pseudo-Protocol",
            category=XSSCategory.PROTOCOL_HANDLER,
            context=ContextType.URI,
            confidence=ConfidenceLevel.CERTAIN,
            pattern=re.compile(r"(?i)\bjavascript\s*:", re.DOTALL),
            explanation="Detected 'javascript:' pseudo-protocol designed to execute code upon navigation.",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-PROTO-DATA",
            name="Data HTML Executable URI",
            category=XSSCategory.PROTOCOL_HANDLER,
            context=ContextType.URI,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(r"(?i)\bdata:\s*text/html\b", re.DOTALL),
            explanation="Detected 'data:text/html' URI scheme embedding inline HTML/JS payloads.",
        ),
        # 4. DOM Sinks & Code Evaluation
        XSSSignatureRule(
            rule_id="SIG-XSS-SINK-WRITE",
            name="Document Write Execution Sink",
            category=XSSCategory.DOM_BASED,
            context=ContextType.JAVASCRIPT,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(r"(?i)\bdocument\s*\.\s*(write|writeln)\s*\(", re.DOTALL),
            explanation="Detected document.write DOM sink that evaluates unparsed HTML/JavaScript.",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-SINK-EVAL",
            name="Dynamic Code Evaluation Function",
            category=XSSCategory.DOM_BASED,
            context=ContextType.JAVASCRIPT,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(
                r"(?i)\b(eval|Function|setTimeout|setInterval)\s*\(\s*['\"]",
                re.DOTALL,
            ),
            explanation="Detected dynamic script evaluation sink executing arbitrary string input.",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-SINK-INNERHTML",
            name="Direct DOM HTML Assignment Sink",
            category=XSSCategory.DOM_BASED,
            context=ContextType.JAVASCRIPT,
            confidence=ConfidenceLevel.MEDIUM,
            pattern=re.compile(r"(?i)\b(innerHTML|outerHTML)\s*=", re.DOTALL),
            explanation="Detected assignment to innerHTML/outerHTML vulnerable to DOM-based XSS.",
        ),
        # 5. Exploitation Proof & Credential Harvesting Gadgets
        XSSSignatureRule(
            rule_id="SIG-XSS-GADGET-COOKIE",
            name="Session Cookie Access Gadget",
            category=XSSCategory.SCRIPT_GADGET,
            context=ContextType.JAVASCRIPT,
            confidence=ConfidenceLevel.HIGH,
            pattern=re.compile(r"(?i)\bdocument\s*\.\s*cookie\b", re.DOTALL),
            explanation="Detected document.cookie access indicative of session token exfiltration.",
        ),
        XSSSignatureRule(
            rule_id="SIG-XSS-GADGET-ALERT",
            name="Modal Dialog PoC Execution",
            category=XSSCategory.SCRIPT_GADGET,
            context=ContextType.JAVASCRIPT,
            confidence=ConfidenceLevel.MEDIUM,
            pattern=re.compile(r"(?i)\b(alert|prompt|confirm)\s*\([^)]*\)", re.DOTALL),
            explanation="Detected standard alert/prompt/confirm modal invocation used in XSS exploits.",
        ),
    ]

    @classmethod
    def match_signatures(cls, input_text: str) -> list[DetectionFinding]:
        """Evaluate input string against all active XSS signature rules."""
        findings: list[DetectionFinding] = []
        if not input_text or not input_text.strip():
            return findings

        clean_text = input_text.strip()
        for rule in cls.RULES:
            match = rule.pattern.search(clean_text)
            if match:
                findings.append(
                    DetectionFinding(
                        finding_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        context=rule.context,
                        confidence=rule.confidence,
                        cwe_id="CWE-79",
                        matched_payload=match.group(0),
                        explanation=rule.explanation,
                        remediation=rule.remediation,
                        details={"pattern": rule.pattern.pattern},
                    )
                )

        return findings

    def scan(self, input_text: str) -> list[DetectionFinding]:
        """Instance method alias for match_signatures."""
        return self.match_signatures(input_text)
