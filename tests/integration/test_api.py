"""Integration tests for FastAPI REST API endpoints."""

from fastapi.testclient import TestClient

from xsslab.api.app import app

client = TestClient(app)


def test_api_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data


def test_api_detect_malicious() -> None:
    response = client.post(
        "/api/v1/detect",
        json={"input_text": "<script>alert('xss')</script>"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"] is True
    assert data["risk_score"] > 50.0
    assert len(data["findings"]) > 0


def test_api_detect_benign() -> None:
    response = client.post(
        "/api/v1/detect",
        json={"input_text": "Normal user search query for products"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"] is False
    assert data["risk_level"] == "CLEAN"


def test_api_sanitize_valid_contexts() -> None:
    # HTML context
    resp_html = client.post(
        "/api/v1/sanitize",
        json={"input_text": "<b>alert(1)</b>", "context": "html"},
    )
    assert resp_html.status_code == 200
    assert "&lt;b&gt;" in resp_html.json()["encoded_text"]

    # JS context
    resp_js = client.post(
        "/api/v1/sanitize",
        json={"input_text": "alert(1)", "context": "js"},
    )
    assert resp_js.status_code == 200
    assert "\\u" in resp_js.json()["encoded_text"]

    # Attr context
    resp_attr = client.post(
        "/api/v1/sanitize",
        json={"input_text": 'foo" onfocus="', "context": "attr"},
    )
    assert resp_attr.status_code == 200
    assert "&#x" in resp_attr.json()["encoded_text"]


def test_api_sanitize_invalid_context() -> None:
    response = client.post(
        "/api/v1/sanitize",
        json={"input_text": "payload", "context": "invalid_ctx"},
    )
    assert response.status_code == 400
    assert "Unsupported context" in response.json()["detail"]


def test_api_simulate_endpoints() -> None:
    # Insecure reflected
    resp_insecure = client.post(
        "/api/v1/simulate",
        json={
            "param_value": "<script>alert(1)</script>",
            "mode": "insecure",
            "lab_type": "reflected",
        },
    )
    assert resp_insecure.status_code == 200
    assert not resp_insecure.json()["executed_safely"]

    # Hardened reflected
    resp_hardened = client.post(
        "/api/v1/simulate",
        json={
            "param_value": "<script>alert(1)</script>",
            "mode": "hardened",
            "lab_type": "reflected",
        },
    )
    assert resp_hardened.status_code == 200
    assert resp_hardened.json()["executed_safely"]

    # Invalid lab type
    resp_invalid = client.post(
        "/api/v1/simulate",
        json={
            "param_value": "test",
            "mode": "insecure",
            "lab_type": "invalid_type",
        },
    )
    assert resp_invalid.status_code == 400


def test_api_csp_audit() -> None:
    # Safe policy
    resp_safe = client.post(
        "/api/v1/audit/csp",
        json={"policy": "default-src 'none'; script-src 'nonce-abc123'; object-src 'none'"},
    )
    assert resp_safe.status_code == 200
    assert resp_safe.json()["is_safe"] is True

    # Unsafe policy
    resp_unsafe = client.post(
        "/api/v1/audit/csp",
        json={"policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'"},
    )
    assert resp_unsafe.status_code == 200
    assert resp_unsafe.json()["is_safe"] is False
    assert len(resp_unsafe.json()["warnings"]) > 0


def test_api_rules() -> None:
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["total_rules"] > 0
    assert len(data["rules"]) == data["total_rules"]
    assert any(r["rule_id"] == "SIG-XSS-TAG-SCRIPT" for r in data["rules"])
