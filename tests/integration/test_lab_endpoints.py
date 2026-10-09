"""Integration tests for dual-mode XSS simulation lab and storage."""

import pytest

from xsslab.lab.endpoints import LabSimExecutor
from xsslab.lab.storage import StoredXSSStorage
from xsslab.models.audit import LabSimRequest


def test_stored_xss_storage_operations() -> None:
    """Test thread-safe in-memory comment storage lifecycle."""
    storage = StoredXSSStorage()
    assert storage.count() == 0

    record1 = storage.add_comment("Bob", "<script>alert(1)</script>", mode="insecure")
    assert record1["id"] == 1
    assert record1["content"] == "<script>alert(1)</script>"
    assert storage.count() == 1

    record2 = storage.add_comment("Charlie", "<script>alert(2)</script>", mode="hardened")
    assert record2["id"] == 2
    assert "&lt;script&gt;" in record2["content"]
    assert storage.count() == 2

    comments = storage.get_comments()
    assert len(comments) == 2
    assert comments[0]["author"] == "Bob"
    assert comments[1]["author"] == "Charlie"

    storage.clear()
    assert storage.count() == 0
    assert len(storage.get_comments()) == 0


def test_simulate_reflected_insecure_malicious() -> None:
    """Verify vulnerable reflected mode executes unsafely when malicious payload injected."""
    executor = LabSimExecutor()
    req = LabSimRequest(
        param_value="<script>alert(document.cookie)</script>",
        mode="insecure",
        lab_type="reflected",
    )
    result = executor.simulate(req)

    assert result.mode == "insecure"
    assert result.lab_type == "reflected"
    assert not result.executed_safely
    assert "<script>alert(document.cookie)</script>" in result.rendered_html
    assert result.audit_verdict is not None
    assert result.audit_verdict.is_malicious


def test_simulate_reflected_hardened_malicious() -> None:
    """Verify hardened reflected mode neutralizes malicious payload and flags safe execution."""
    executor = LabSimExecutor()
    req = LabSimRequest(
        param_value="<script>alert(document.cookie)</script>",
        mode="hardened",
        lab_type="reflected",
    )
    result = executor.simulate(req)

    assert result.mode == "hardened"
    assert result.lab_type == "reflected"
    assert result.executed_safely
    assert "<script>" not in result.rendered_html
    assert "&lt;script&gt;" in result.rendered_html
    assert result.audit_verdict is not None
    assert result.audit_verdict.is_malicious


def test_simulate_reflected_insecure_benign() -> None:
    """Verify vulnerable reflected mode is marked safe when input is benign."""
    executor = LabSimExecutor()
    req = LabSimRequest(
        param_value="Alice Smith",
        mode="insecure",
        lab_type="reflected",
    )
    result = executor.simulate(req)

    assert result.mode == "insecure"
    assert result.executed_safely
    assert "Alice Smith" in result.rendered_html
    assert result.audit_verdict is not None
    assert not result.audit_verdict.is_malicious


def test_simulate_stored_insecure_and_hardened() -> None:
    """Verify stored comments in both insecure and hardened modes."""
    storage = StoredXSSStorage()
    executor = LabSimExecutor(storage=storage)

    # Insecure attack
    req_insecure = LabSimRequest(
        param_value="<img src=x onerror=alert(1)>",
        mode="insecure",
        lab_type="stored",
    )
    res_insecure = executor.simulate(req_insecure)
    assert not res_insecure.executed_safely
    assert "<img src=x onerror=alert(1)>" in res_insecure.rendered_html
    assert res_insecure.audit_verdict is not None
    assert res_insecure.audit_verdict.is_malicious

    # Hardened attack
    req_hardened = LabSimRequest(
        param_value="<img src=x onerror=alert(1)>",
        mode="hardened",
        lab_type="stored",
    )
    res_hardened = executor.simulate(req_hardened)
    assert res_hardened.executed_safely
    assert "<img src=x onerror=alert(1)>" not in res_hardened.rendered_html
    assert "&lt;img" in res_hardened.rendered_html


def test_simulate_dom_insecure_and_hardened() -> None:
    """Verify DOM simulation using innerHTML (insecure) vs textContent (hardened)."""
    executor = LabSimExecutor()

    # Insecure DOM sink
    req_insecure = LabSimRequest(
        param_value='"><svg onload=alert(1)>',
        mode="insecure",
        lab_type="dom",
    )
    res_insecure = executor.simulate(req_insecure)
    assert not res_insecure.executed_safely
    assert "innerHTML" in res_insecure.rendered_html
    assert '"><svg onload=alert(1)>' in res_insecure.rendered_html

    # Hardened DOM property
    req_hardened = LabSimRequest(
        param_value='"><svg onload=alert(1)>',
        mode="hardened",
        lab_type="dom",
    )
    res_hardened = executor.simulate(req_hardened)
    assert res_hardened.executed_safely
    assert "textContent" in res_hardened.rendered_html
    assert "<svg" not in res_hardened.rendered_html


def test_simulate_invalid_lab_type() -> None:
    """Verify ValueError is raised when invalid lab_type requested."""
    executor = LabSimExecutor()
    req = LabSimRequest(
        param_value="test",
        mode="insecure",
        lab_type="invalid_type",
    )
    with pytest.raises(ValueError, match="Unknown lab_type 'invalid_type'"):
        executor.simulate(req)
