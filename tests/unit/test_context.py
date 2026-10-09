"""Unit tests for HTMLContextAnalyzer."""

from xsslab.detector.context import HTMLContextAnalyzer
from xsslab.models.finding import ContextType, XSSCategory


def test_context_empty_and_whitespace() -> None:
    """Verify empty inputs return UNKNOWN context with no findings."""
    ctxs, findings = HTMLContextAnalyzer.analyze_contexts("")
    assert ctxs == [ContextType.UNKNOWN]
    assert findings == []

    ctxs_ws, findings_ws = HTMLContextAnalyzer.analyze_contexts("   \n\t  ")
    assert ctxs_ws == [ContextType.UNKNOWN]
    assert findings_ws == []


def test_context_uri_pseudo_protocols() -> None:
    """Verify pseudo-protocol detection (javascript:, data:, vbscript:)."""
    payload = "javascript:alert(document.cookie)"
    ctxs, findings = HTMLContextAnalyzer.analyze_contexts(payload)
    assert ContextType.URI in ctxs
    assert any(f.finding_id == "CTX-URI-01" for f in findings)
    assert any(f.category == XSSCategory.PROTOCOL_HANDLER for f in findings)

    data_payload = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    data_ctxs, _ = HTMLContextAnalyzer.analyze_contexts(data_payload)
    assert ContextType.URI in data_ctxs


def test_context_inline_event_handlers() -> None:
    """Verify inline event handlers trigger ATTRIBUTE context and findings."""
    payload = '<img src="x" onerror="alert(1)">'
    ctxs, findings = HTMLContextAnalyzer.analyze_contexts(payload)
    assert ContextType.ATTRIBUTE in ctxs
    assert ContextType.HTML_BODY in ctxs
    assert any(f.finding_id == "CTX-ATTR-01" for f in findings)
    assert any(f.category == XSSCategory.EVENT_HANDLER for f in findings)


def test_context_script_blocks_and_breakouts() -> None:
    """Verify script tags and closing script breakouts."""
    script_payload = "<script>alert(window.origin)</script>"
    ctxs, findings = HTMLContextAnalyzer.analyze_contexts(script_payload)
    assert ContextType.JAVASCRIPT in ctxs
    assert ContextType.HTML_BODY in ctxs
    assert any(f.finding_id == "CTX-TAG-SCRIPT" for f in findings)

    breakout_payload = '"; alert(1); </script><b>Injected</b>'
    b_ctxs, b_findings = HTMLContextAnalyzer.analyze_contexts(breakout_payload)
    assert ContextType.JAVASCRIPT in b_ctxs
    assert any(f.finding_id == "CTX-JS-01" for f in b_findings)


def test_context_dangerous_html_tags() -> None:
    """Verify iframe, svg, and object tag detections."""
    payloads = [
        '<iframe src="http://attacker.com/steal"></iframe>',
        "<svg onload=alert(1)>",
        "<object data=test.swf></object>",
    ]
    for p in payloads:
        ctxs, findings = HTMLContextAnalyzer.analyze_contexts(p)
        assert ContextType.HTML_BODY in ctxs
        assert any("CTX-TAG-" in f.finding_id for f in findings)


def test_context_benign_text() -> None:
    """Verify plain safe text is evaluated cleanly."""
    benign = "Just a friendly message discussing cybersecurity tools."
    ctxs, findings = HTMLContextAnalyzer.analyze_contexts(benign)
    assert ContextType.HTML_BODY in ctxs
    assert len(findings) == 0
