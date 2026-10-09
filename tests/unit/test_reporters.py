"""Unit tests for xsslab reporting subsystem (JSON, Markdown, SARIF, Factory)."""

import json

import pytest

from xsslab.detector.engine import XSSDetectionEngine
from xsslab.models.audit import XSSAuditResult
from xsslab.reporters.factory import ReporterFactory
from xsslab.reporters.json_reporter import JSONReporter
from xsslab.reporters.markdown_reporter import MarkdownReporter
from xsslab.reporters.sarif_reporter import SARIFReporter


@pytest.fixture
def sample_malicious_result() -> XSSAuditResult:
    engine = XSSDetectionEngine()
    return engine.analyze("<script>alert(document.cookie)</script>")


@pytest.fixture
def sample_benign_result() -> XSSAuditResult:
    engine = XSSDetectionEngine()
    return engine.analyze("Hello, Alice! Welcome to our website.")


def test_json_reporter_single(sample_malicious_result: XSSAuditResult) -> None:
    reporter = JSONReporter()
    output = reporter.generate(sample_malicious_result)
    data = json.loads(output)

    assert data["is_malicious"] is True
    assert data["risk_score"] > 50.0
    assert len(data["findings"]) > 0
    assert "sanitized_output" in data


def test_json_reporter_batch(
    sample_malicious_result: XSSAuditResult,
    sample_benign_result: XSSAuditResult,
) -> None:
    reporter = JSONReporter()
    output = reporter.generate_batch([sample_malicious_result, sample_benign_result])
    data = json.loads(output)

    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["is_malicious"] is True
    assert data[1]["is_malicious"] is False


def test_markdown_reporter_single_malicious(sample_malicious_result: XSSAuditResult) -> None:
    reporter = MarkdownReporter()
    output = reporter.generate(sample_malicious_result)

    assert "# XSS Security Audit Report" in output
    assert "CRITICAL / MALICIOUS" in output
    assert "## Inspected Payload" in output
    assert "## Recommended Sanitized Output" in output
    assert "| ID | Rule Name | Category | Confidence | Matched Payload |" in output


def test_markdown_reporter_single_benign(sample_benign_result: XSSAuditResult) -> None:
    reporter = MarkdownReporter()
    output = reporter.generate(sample_benign_result)

    assert "# XSS Security Audit Report" in output
    assert "CLEAN / BENIGN" in output
    assert "No cross-site scripting patterns" in output


def test_markdown_reporter_batch(
    sample_malicious_result: XSSAuditResult,
    sample_benign_result: XSSAuditResult,
) -> None:
    reporter = MarkdownReporter()
    output = reporter.generate_batch([sample_malicious_result, sample_benign_result])

    assert "# Batch XSS Security Audit Report" in output
    assert "**Total Payloads Audited:** `2`" in output
    assert "**Malicious Payloads Detected:** `1`" in output
    assert "| 1 |" in output
    assert "| 2 |" in output


def test_sarif_reporter_single(sample_malicious_result: XSSAuditResult) -> None:
    reporter = SARIFReporter()
    output = reporter.generate(sample_malicious_result)
    data = json.loads(output)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "xsslab"
    assert len(run["results"]) > 0
    assert run["results"][0]["level"] in ("error", "warning", "note")


def test_sarif_reporter_batch(
    sample_malicious_result: XSSAuditResult,
    sample_benign_result: XSSAuditResult,
) -> None:
    reporter = SARIFReporter()
    output = reporter.generate_batch([sample_malicious_result, sample_benign_result])
    data = json.loads(output)

    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert len(run["results"]) >= 1


def test_reporter_factory() -> None:
    assert isinstance(ReporterFactory.create_reporter("json"), JSONReporter)
    assert isinstance(ReporterFactory.create_reporter("markdown"), MarkdownReporter)
    assert isinstance(ReporterFactory.create_reporter("md"), MarkdownReporter)
    assert isinstance(ReporterFactory.create_reporter("sarif"), SARIFReporter)

    with pytest.raises(ValueError, match="Unsupported report format 'xml'"):
        ReporterFactory.create_reporter("xml")
