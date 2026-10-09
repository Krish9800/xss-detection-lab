"""Unit tests for XSSSignatureEngine multi-vector pattern scanner."""

import pytest

from xsslab.detector.signatures import XSSSignatureEngine
from xsslab.models.finding import XSSCategory


@pytest.fixture
def scanner() -> XSSSignatureEngine:
    """Fixture providing initialized XSSSignatureEngine."""
    return XSSSignatureEngine()


def test_signature_empty_input(scanner: XSSSignatureEngine) -> None:
    """Verify empty and whitespace inputs return no findings."""
    assert scanner.scan("") == []
    assert scanner.scan("   \n\t  ") == []


def test_signature_dangerous_tags(scanner: XSSSignatureEngine) -> None:
    """Verify dangerous executable tag patterns match correctly."""
    samples = [
        ("<script>alert(1)</script>", "SIG-XSS-TAG-SCRIPT"),
        ("<iframe src='evil.com'></iframe>", "SIG-XSS-TAG-IFRAME"),
        ("<svg onload=alert(1)>", "SIG-XSS-TAG-SVG"),
        ("<object data='exploit.swf'></object>", "SIG-XSS-TAG-OBJECT"),
        ("<base href='http://attacker.com/'>", "SIG-XSS-TAG-BASE"),
    ]
    for payload, expected_rule in samples:
        findings = scanner.scan(payload)
        assert any(f.finding_id == expected_rule for f in findings), f"Failed on: {payload}"
        assert any(f.category == XSSCategory.HTML_TAG_INJECTION for f in findings)


def test_signature_event_handlers(scanner: XSSSignatureEngine) -> None:
    """Verify automatic and user-driven event handler matches."""
    auto_handlers = [
        '<img src=x onerror="alert(1)">',
        "<body onload=steal()>",
    ]
    for p in auto_handlers:
        findings = scanner.scan(p)
        assert any(f.finding_id == "SIG-XSS-EVENT-LOAD" for f in findings)
        assert any(f.category == XSSCategory.EVENT_HANDLER for f in findings)

    user_handlers = [
        '<a href="#" onclick="alert(1)">Click</a>',
        '<div onmouseover="leak()">Hover</div>',
    ]
    for p in user_handlers:
        findings = scanner.scan(p)
        assert any(f.finding_id == "SIG-XSS-EVENT-USER" for f in findings)


def test_signature_protocols(scanner: XSSSignatureEngine) -> None:
    """Verify javascript: and data: pseudo-protocols."""
    js_proto = "<a href='javascript:alert(1)'>Link</a>"
    findings = scanner.scan(js_proto)
    assert any(f.finding_id == "SIG-XSS-PROTO-JS" for f in findings)

    data_proto = '<iframe src="data:text/html;base64,..."></iframe>'
    findings_data = scanner.scan(data_proto)
    assert any(f.finding_id == "SIG-XSS-PROTO-DATA" for f in findings_data)


def test_signature_dom_sinks_and_gadgets(scanner: XSSSignatureEngine) -> None:
    """Verify document.write, eval, innerHTML, and document.cookie detections."""
    sinks = [
        ("document.write(userInput);", "SIG-XSS-SINK-WRITE"),
        ("eval('var a = ' + payload);", "SIG-XSS-SINK-EVAL"),
        ("element.innerHTML = untrustedHTML;", "SIG-XSS-SINK-INNERHTML"),
        ("fetch('/log?c=' + document.cookie);", "SIG-XSS-GADGET-COOKIE"),
        ("alert('XSS');", "SIG-XSS-GADGET-ALERT"),
    ]
    for code, expected_rule in sinks:
        findings = scanner.scan(code)
        assert any(f.finding_id == expected_rule for f in findings), f"Failed on: {code}"


def test_signature_benign_inputs(scanner: XSSSignatureEngine) -> None:
    """Verify safe HTML markup and standard text trigger no signature matches."""
    benign_samples = [
        "Welcome to our secure corporate portal.",
        "<p>This is a safe paragraph with <b>bold</b> text.</p>",
        "<a href='https://example.com/about'>About Us</a>",
        "span { font-size: 14px; }",
        "user_name_12345",
        "test.user@company.local",
    ]
    for sample in benign_samples:
        findings = scanner.scan(sample)
        assert findings == [], f"False positive on benign sample: {sample}"
