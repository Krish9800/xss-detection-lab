"""Unit tests verifying domain models and taxonomy enums."""

from xsslab.models.audit import (
    EncodingRequest,
    EncodingResult,
    LabSimRequest,
    LabSimResult,
    XSSAuditResult,
)
from xsslab.models.finding import (
    ConfidenceLevel,
    ContextType,
    DetectionFinding,
    XSSCategory,
)


def test_taxonomy_enums_values() -> None:
    """Verify enumeration values and string representations."""
    assert XSSCategory.REFLECTED.value == "REFLECTED"
    assert XSSCategory.STORED.value == "STORED"
    assert XSSCategory.DOM_BASED.value == "DOM_BASED"
    assert XSSCategory.EVENT_HANDLER.value == "EVENT_HANDLER"

    assert ContextType.HTML_BODY.value == "HTML_BODY"
    assert ContextType.ATTRIBUTE.value == "ATTRIBUTE"
    assert ContextType.JAVASCRIPT.value == "JAVASCRIPT"
    assert ContextType.URI.value == "URI"

    assert ConfidenceLevel.CERTAIN.value == "CERTAIN"
    assert ConfidenceLevel.HIGH.value == "HIGH"


def test_detection_finding_instantiation() -> None:
    """Verify DetectionFinding instantiation with defaults and custom details."""
    finding = DetectionFinding(
        finding_id="RULE-TAG-01",
        rule_name="Dangerous Script Tag Injection",
        category=XSSCategory.HTML_TAG_INJECTION,
        context=ContextType.HTML_BODY,
        confidence=ConfidenceLevel.CERTAIN,
        matched_payload="<script>alert(1)</script>",
        explanation="Inline script element executes arbitrary JavaScript in victim origin.",
    )
    assert finding.cwe_id == "CWE-79"
    assert "Content Security Policy" in finding.remediation
    assert finding.details == {}


def test_audit_result_model() -> None:
    """Verify XSSAuditResult model serialization and validation."""
    result = XSSAuditResult(
        input_text="<img src=x onerror=alert(1)>",
        is_malicious=True,
        risk_score=95.0,
        risk_level="MALICIOUS",
        detected_contexts=[ContextType.ATTRIBUTE, ContextType.HTML_BODY],
    )
    assert result.is_malicious is True
    assert result.risk_score == 95.0
    assert len(result.detected_contexts) == 2

    # Verify JSON dump
    data = result.model_dump(mode="json")
    assert data["is_malicious"] is True
    assert "analyzed_at" in data


def test_encoding_and_lab_models() -> None:
    """Verify encoding requests/results and lab simulation models."""
    enc_req = EncodingRequest(input_text="<b>Hello</b>", context=ContextType.HTML_BODY)
    assert enc_req.context == ContextType.HTML_BODY

    enc_res = EncodingResult(
        original_text="<b>Hello</b>",
        context=ContextType.HTML_BODY,
        encoded_text="&lt;b&gt;Hello&lt;/b&gt;",
    )
    assert enc_res.encoded_text == "&lt;b&gt;Hello&lt;/b&gt;"

    lab_req = LabSimRequest(param_value="<script>alert(1)</script>")
    assert lab_req.mode == "insecure"
    assert lab_req.lab_type == "reflected"

    lab_res = LabSimResult(
        raw_input="test",
        mode="hardened",
        lab_type="reflected",
        rendered_html="<div>test</div>",
        executed_safely=True,
    )
    assert lab_res.executed_safely is True
