"""Unit tests for XSSHeuristicAnalyzer obfuscation and entity detection."""

import pytest

from xsslab.detector.heuristics import XSSHeuristicAnalyzer
from xsslab.models.finding import XSSCategory


@pytest.fixture
def analyzer() -> XSSHeuristicAnalyzer:
    """Fixture providing initialized XSSHeuristicAnalyzer."""
    return XSSHeuristicAnalyzer()


def test_heuristic_empty_input(analyzer: XSSHeuristicAnalyzer) -> None:
    """Verify empty input returns zeroed metrics and no findings."""
    metrics, findings = analyzer.analyze("")
    assert metrics.entropy == 0.0
    assert metrics.anomaly_score == 0.0
    assert findings == []


def test_shannon_entropy_calculation() -> None:
    """Verify Shannon entropy calculations on various distributions."""
    assert XSSHeuristicAnalyzer.calculate_shannon_entropy("") == 0.0
    assert XSSHeuristicAnalyzer.calculate_shannon_entropy("aaaaaaa") == 0.0

    normal_entropy = XSSHeuristicAnalyzer.calculate_shannon_entropy("standard user query")
    assert 2.5 <= normal_entropy <= 4.5


def test_html_entity_obfuscation(analyzer: XSSHeuristicAnalyzer) -> None:
    """Verify detection of hex, decimal, and named entity bypasses."""
    # Hex and decimal entities
    payload = "&#x3C;script&#x3E;&#60;img src=x onerror=alert(1)&#62;"
    metrics, findings = analyzer.analyze(payload)
    assert metrics.entity_count >= 3
    assert any(f.finding_id == "HEUR-XSS-ENTITY-01" for f in findings)
    assert any(f.category == XSSCategory.HEURISTIC_ANOMALY for f in findings)

    # Named entity bypass
    named_payload = "javascript&colon;alert(1)"
    n_metrics, n_findings = analyzer.analyze(named_payload)
    assert n_metrics.entity_count >= 1
    assert any(f.finding_id == "HEUR-XSS-ENTITY-01" for f in n_findings)


def test_js_unicode_hex_escapes(analyzer: XSSHeuristicAnalyzer) -> None:
    """Verify detection of multiple JavaScript Unicode/hex escape sequences."""
    payload = r"\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e"
    metrics, findings = analyzer.analyze(payload)
    assert any(f.finding_id == "HEUR-XSS-JS-ESCAPE-01" for f in findings)
    assert metrics.anomaly_score >= 0.2


def test_fromcharcode_and_atob(analyzer: XSSHeuristicAnalyzer) -> None:
    """Verify detection of dynamic decoders (String.fromCharCode and atob)."""
    samples = [
        "String.fromCharCode(97,108,101,114,116,40,49,41)",
        "eval(atob('YWxlcnQoMSk='))",
    ]
    for s in samples:
        metrics, findings = analyzer.analyze(s)
        assert any(f.finding_id == "HEUR-XSS-CHARCODE-01" for f in findings)
        assert metrics.anomaly_score >= 0.25


def test_mixed_case_tags(analyzer: XSSHeuristicAnalyzer) -> None:
    """Verify mixed-case tag filter evasion detection."""
    payload = "<sCrIpt>alert(1)</ScRiPt>"
    metrics, findings = analyzer.analyze(payload)
    assert metrics.has_mixed_case_tags is True
    assert any(f.finding_id == "HEUR-XSS-MIXEDCASE-01" for f in findings)


def test_benign_text_heuristics(analyzer: XSSHeuristicAnalyzer) -> None:
    """Verify safe plain text produces zero findings and negligible anomaly score."""
    benign = "Hello, I would like to order two items please."
    metrics, findings = analyzer.analyze(benign)
    assert metrics.anomaly_score <= 0.1
    assert metrics.entity_count == 0
    assert findings == []
