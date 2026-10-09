"""HTML lexical and execution context analyzer for XSS vector localization."""

import re
from html.parser import HTMLParser

from xsslab.models.finding import (
    ConfidenceLevel,
    ContextType,
    DetectionFinding,
    XSSCategory,
)


class _ContextHTMLParser(HTMLParser):
    """Subclassed HTML parser collecting tags, attributes, and script contents."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []
        self.in_script: bool = False
        self.in_style: bool = False
        self.script_content: list[str] = []
        self.parse_errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        self.tags.append(tag_lower)
        self.attrs.extend(attrs)
        if tag_lower == "script":
            self.in_script = True
        elif tag_lower == "style":
            self.in_style = True

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower == "script":
            self.in_script = False
        elif tag_lower == "style":
            self.in_style = False

    def handle_data(self, data: str) -> None:
        if self.in_script:
            self.script_content.append(data)


class HTMLContextAnalyzer:
    """Audits input strings and HTML fragments to identify targeted browser execution contexts."""

    # Contextual pattern signatures
    URI_SCHEME_PATTERN = re.compile(
        r"(?i)\b(javascript|vbscript|data|file):",
    )
    EVENT_HANDLER_PATTERN = re.compile(
        r"(?i)\bon[a-z]{3,20}\s*=",
    )
    ATTR_BREAKOUT_PATTERN = re.compile(
        r"""(?i)["'][^>]*\bon[a-z]{3,20}\s*=""",
    )
    JS_BREAKOUT_PATTERN = re.compile(
        r"""(?i)(</script>|["']\s*;\s*[a-zA-Z_$]|["']\s*[-+*/&|]\s*[a-zA-Z_$])""",
    )
    STYLE_EXPRESSION_PATTERN = re.compile(
        r"(?i)(style\s*=.*expression\s*\(|@import\b|url\s*\(\s*['\"]?javascript:)",
    )

    @classmethod
    def analyze_contexts(cls, input_text: str) -> tuple[list[ContextType], list[DetectionFinding]]:
        """Identify targeted browser contexts and surface structural escape anomalies.

        Args:
            input_text: The untrusted input or HTML fragment string.

        Returns:
            A tuple of (detected ContextTypes, list of contextual DetectionFindings).
        """
        contexts: set[ContextType] = set()
        findings: list[DetectionFinding] = []

        if not input_text or not input_text.strip():
            return [ContextType.UNKNOWN], findings

        text = input_text.strip()

        # 1. Check URI / Pseudo-Protocol Context
        if cls.URI_SCHEME_PATTERN.search(text):
            contexts.add(ContextType.URI)
            match = cls.URI_SCHEME_PATTERN.search(text)
            matched_str = match.group(0) if match else "javascript:"
            findings.append(
                DetectionFinding(
                    finding_id="CTX-URI-01",
                    rule_name="Dangerous Pseudo-Protocol in URI Context",
                    category=XSSCategory.PROTOCOL_HANDLER,
                    context=ContextType.URI,
                    confidence=ConfidenceLevel.CERTAIN,
                    matched_payload=matched_str,
                    explanation=(
                        f"Detected '{matched_str}' pseudo-protocol intended to execute script "
                        "when navigated or loaded by an anchor or iframe."
                    ),
                    remediation="Validate URL schemes strictly against an allowlist ('http', 'https').",
                )
            )

        # 2. Check Attribute Breakout & Inline Event Handlers
        if cls.EVENT_HANDLER_PATTERN.search(text):
            contexts.add(ContextType.ATTRIBUTE)
            match = cls.EVENT_HANDLER_PATTERN.search(text)
            handler = match.group(0) if match else "onerror="
            findings.append(
                DetectionFinding(
                    finding_id="CTX-ATTR-01",
                    rule_name="Inline Event Handler Attribute Injection",
                    category=XSSCategory.EVENT_HANDLER,
                    context=ContextType.ATTRIBUTE,
                    confidence=ConfidenceLevel.CERTAIN,
                    matched_payload=handler,
                    explanation=(
                        f"Detected inline DOM event handler '{handler}' "
                        "designed to execute script when DOM events trigger."
                    ),
                    remediation="Disallow inline event handlers and apply attribute-safe hex encoding.",
                )
            )

        if cls.ATTR_BREAKOUT_PATTERN.search(text):
            contexts.add(ContextType.ATTRIBUTE)

        # 3. Check JavaScript Context and Script Tag Breakouts
        if "</script>" in text.lower():
            contexts.add(ContextType.JAVASCRIPT)
            findings.append(
                DetectionFinding(
                    finding_id="CTX-JS-01",
                    rule_name="Script Block Delimiter Breakout",
                    category=XSSCategory.SCRIPT_GADGET,
                    context=ContextType.JAVASCRIPT,
                    confidence=ConfidenceLevel.HIGH,
                    matched_payload="</script>",
                    explanation=(
                        "Detected closing '</script>' delimiter utilized to break out of "
                        "inline script blocks into HTML body execution."
                    ),
                    remediation="Ensure JSON serialization encodes closing tag sequences (<\\/script>).",
                )
            )

        if cls.JS_BREAKOUT_PATTERN.search(text) or "<script" in text.lower():
            contexts.add(ContextType.JAVASCRIPT)

        # 4. Check CSS / Style Context
        if cls.STYLE_EXPRESSION_PATTERN.search(text) or "<style" in text.lower():
            contexts.add(ContextType.STYLE)

        # 5. HTML Body Context Parsing via HTMLParser
        if ("<" in text and ">" in text) or not contexts:
            contexts.add(ContextType.HTML_BODY)

        parser = _ContextHTMLParser()
        try:
            parser.feed(text)
        except Exception:
            # HTML parsing exception indicates malformed tag syntax often used in WAF evasion
            findings.append(
                DetectionFinding(
                    finding_id="CTX-HTML-MALFORMED",
                    rule_name="Malformed HTML Syntax Breakout",
                    category=XSSCategory.HTML_TAG_INJECTION,
                    context=ContextType.HTML_BODY,
                    confidence=ConfidenceLevel.MEDIUM,
                    matched_payload=text[:60],
                    explanation="HTML parser encountered malformed tag structure.",
                )
            )

        # If dangerous tags are present in parser
        dangerous_tags = {"script", "iframe", "object", "embed", "svg", "math", "base"}
        for tag in parser.tags:
            if tag in dangerous_tags:
                contexts.add(ContextType.HTML_BODY)
                findings.append(
                    DetectionFinding(
                        finding_id=f"CTX-TAG-{tag.upper()}",
                        rule_name=f"Dangerous <{tag}> Element Presence",
                        category=XSSCategory.HTML_TAG_INJECTION,
                        context=ContextType.HTML_BODY,
                        confidence=ConfidenceLevel.CERTAIN,
                        matched_payload=f"<{tag}>",
                        explanation=f"Detected high-risk HTML element '<{tag}>' capable of code execution.",
                        details={"tag": tag},
                    )
                )

        return sorted(contexts, key=lambda c: c.value), findings
