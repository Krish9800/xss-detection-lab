"""Adversarial and evasion robustness security tests for xsslab."""

import time

from xsslab.detector.engine import XSSDetectionEngine


def test_adversarial_case_variation_evasion() -> None:
    """Verify engine detects mixed and alternating case tag/protocol vectors."""
    engine = XSSDetectionEngine()
    vectors = [
        "<sCrIpt>alert(1)</sCrIpt>",
        "<ScRiPt SrC='https://evil.corp/payload.js'></sCrIpt>",
        "<iFrAmE sRc='javascript:alert(1)'></iFrAmE>",
        "jAvAsCrIpT:alert(1)",
        "<sVg OnLoAd=alert(1)>",
    ]
    for vector in vectors:
        result = engine.analyze(vector)
        assert result.is_malicious, f"Failed to detect case evasion vector: {vector}"
        assert result.risk_score >= 50.0


def test_adversarial_whitespace_and_slash_evasion() -> None:
    """Verify engine detects whitespace variations, slash delimiters, and newline breaks."""
    engine = XSSDetectionEngine()
    vectors = [
        "<img/src=x/onerror=alert(1)>",
        "<svg\tonload=alert(1)>",
        "<svg\nonload=alert(1)>",
        '<iframe\r\nsrc="javascript:alert(1)"></iframe>',
        "<body \t onerror=alert(1)>",
    ]
    for vector in vectors:
        result = engine.analyze(vector)
        assert result.is_malicious, f"Failed to detect delimiter evasion: {vector}"


def test_adversarial_html_entity_and_hex_evasion() -> None:
    """Verify engine detects obfuscated decimal and hex entity representations."""
    engine = XSSDetectionEngine()
    vectors = [
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>',
    ]
    for vector in vectors:
        result = engine.analyze(vector)
        assert result.is_malicious, f"Failed to detect entity-encoded vector: {vector}"


def test_adversarial_nested_and_malformed_tags() -> None:
    """Verify engine handles nested/filter-bypass tag strings safely."""
    engine = XSSDetectionEngine()
    vectors = [
        "<scr<script>ipt>alert(1)</script>",
        '<<SCRIPT>alert("XSS");//<</SCRIPT>',
        '<img src="x" onerror="alert(1)">',
    ]
    for vector in vectors:
        result = engine.analyze(vector)
        assert result.is_malicious, f"Failed to detect malformed vector: {vector}"


def test_redos_and_long_payload_resilience() -> None:
    """Verify engine evaluates large payloads without ReDoS catastrophic backtracking."""
    engine = XSSDetectionEngine()

    # 10,000-character repetitive payload
    repetitive_text = '<div class="content">' + ("a" * 10000) + "</div>"
    start = time.perf_counter()
    result_benign = engine.analyze(repetitive_text)
    duration = time.perf_counter() - start

    assert not result_benign.is_malicious
    assert duration < 0.5, f"Analysis took too long ({duration:.2f}s), potential ReDoS risk"

    # Large payload with trailing XSS injection
    large_malicious = ("a" * 8000) + "<script>alert(1)</script>"
    start = time.perf_counter()
    result_malicious = engine.analyze(large_malicious)
    duration = time.perf_counter() - start

    assert result_malicious.is_malicious
    assert duration < 0.5, f"Analysis took too long ({duration:.2f}s)"
