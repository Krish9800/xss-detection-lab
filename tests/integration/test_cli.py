"""Integration tests for xsslab CLI commands and user workflows."""

import json
from pathlib import Path

from typer.testing import CliRunner

from xsslab.cli.main import app

runner = CliRunner(env={"COLUMNS": "160"})


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output
    assert "System Information" in result.output


def test_cli_audit_benign() -> None:
    result = runner.invoke(app, ["audit", "Hello Alice"])
    assert result.exit_code == 0
    assert "CLEAN" in result.output


def test_cli_audit_malicious() -> None:
    result = runner.invoke(app, ["audit", "<script>alert(1)</script>"])
    assert result.exit_code == 1
    assert "MALICIOUS" in result.output
    assert "SIG-XSS-TAG-SCRIPT" in result.output


def test_cli_audit_json_format() -> None:
    result = runner.invoke(app, ["audit", "<script>alert(1)</script>", "--format", "json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["is_malicious"] is True


def test_cli_audit_invalid_format() -> None:
    result = runner.invoke(app, ["audit", "<script>alert(1)</script>", "--format", "xml"])
    assert result.exit_code == 2
    assert "Unsupported report format" in result.output


def test_cli_audit_file_output(tmp_path: Path) -> None:
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["audit", "alert(1)", "--format", "json", "--output", str(out_file)],
    )
    assert result.exit_code in (0, 1)
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "input_text" in data


def test_cli_analyze_file(tmp_path: Path) -> None:
    payloads_file = tmp_path / "payloads.txt"
    payloads_file.write_text(
        "<script>alert(1)</script>\nHello World\n<img src=x onerror=alert(2)>\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["analyze", str(payloads_file)])
    assert result.exit_code == 1
    assert "Batch XSS Audit" in result.output


def test_cli_analyze_file_nonexistent(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.txt"
    result = runner.invoke(app, ["analyze", str(missing_file)])
    assert result.exit_code == 2
    assert "does not exist" in result.output.replace("\n", " ")


def test_cli_analyze_file_empty(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("", encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(empty_file)])
    assert result.exit_code == 0
    assert "File is empty" in result.output


def test_cli_encode() -> None:
    result_html = runner.invoke(app, ["encode", "<b>alert</b>", "--context", "html"])
    assert result_html.exit_code == 0
    assert "&lt;b&gt;" in result_html.output

    result_js = runner.invoke(app, ["encode", "alert(1)", "--context", "js"])
    assert result_js.exit_code == 0
    assert "\\u" in result_js.output

    result_invalid = runner.invoke(app, ["encode", "test", "--context", "unknown"])
    assert result_invalid.exit_code == 2
    assert "Unsupported context" in result_invalid.output


def test_cli_benchmark() -> None:
    result = runner.invoke(app, ["benchmark"])
    assert result.exit_code == 0
    assert "Benchmark Results" in result.output
    assert "Accuracy" in result.output


def test_cli_lab() -> None:
    # Insecure reflected
    res_insecure = runner.invoke(
        app,
        ["lab", "<script>alert(1)</script>", "--mode", "insecure", "--type", "reflected"],
    )
    assert res_insecure.exit_code == 1
    assert "VULNERABLE" in res_insecure.output

    # Hardened reflected
    res_hardened = runner.invoke(
        app,
        ["lab", "<script>alert(1)</script>", "--mode", "hardened", "--type", "reflected"],
    )
    assert res_hardened.exit_code == 0
    assert "SAFE" in res_hardened.output

    # Invalid lab type
    res_invalid = runner.invoke(
        app,
        ["lab", "test", "--type", "invalid_sink"],
    )
    assert res_invalid.exit_code == 2
    assert "Unknown lab_type" in res_invalid.output
