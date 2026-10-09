"""Unit tests for ContextAwareEncoder and CSPPolicyGenerator."""

from xsslab.defense.csp import CSPPolicyGenerator
from xsslab.defense.encoder import ContextAwareEncoder
from xsslab.models.finding import ContextType


def test_encode_for_html() -> None:
    """Verify HTML body context entity encoding."""
    raw = "<script>alert('XSS')</script>"
    encoded = ContextAwareEncoder.encode_for_html(raw)
    assert "<" not in encoded
    assert ">" not in encoded
    assert "&lt;script&gt;" in encoded
    assert "&#x27;" in encoded
    assert "&#x2F;" in encoded


def test_encode_for_attribute() -> None:
    """Verify HTML attribute context hexadecimal entity encoding."""
    raw = '"> <img onerror="alert(1)">'
    encoded = ContextAwareEncoder.encode_for_attribute(raw)
    assert '"' not in encoded
    assert "<" not in encoded
    assert ">" not in encoded
    assert "&#x22;" in encoded
    assert "&#x3C;" in encoded or "&#x3c;" in encoded.lower()


def test_encode_for_javascript() -> None:
    """Verify JavaScript string context Unicode escaping."""
    raw = '"; alert(1); //'
    encoded = ContextAwareEncoder.encode_for_javascript(raw)
    assert '"' not in encoded
    assert ";" not in encoded
    assert r"\u0022" in encoded
    assert r"\u003B" in encoded or r"\u003b" in encoded.lower()


def test_encode_for_uri() -> None:
    """Verify URI scheme validation and percent encoding."""
    # Malicious executable schemes blocked
    assert ContextAwareEncoder.encode_for_uri("javascript:alert(1)") == "about:blank"
    assert ContextAwareEncoder.encode_for_uri("data:text/html,...") == "about:blank"
    assert ContextAwareEncoder.encode_for_uri("vbscript:msgbox(1)") == "about:blank"

    # Valid URLs preserved and encoded
    safe_url = "https://example.com/search?q=cyber security&sort=asc"
    encoded_url = ContextAwareEncoder.encode_for_uri(safe_url)
    assert encoded_url.startswith("https://example.com/search")
    assert "%20" in encoded_url


def test_encode_for_style() -> None:
    """Verify CSS style expression and protocol neutralization."""
    css_payload = "width: expression(alert(1)); background: url('javascript:alert(2)');"
    sanitized = ContextAwareEncoder.encode_for_style(css_payload)
    assert "expression" not in sanitized
    assert "javascript:" not in sanitized
    assert "blocked_expr" in sanitized


def test_encode_dispatch_function() -> None:
    """Verify encode dispatch method routes correctly across all ContextTypes."""
    raw = "<test>"
    assert "&lt;test&gt;" in ContextAwareEncoder.encode(raw, ContextType.HTML_BODY)
    assert "&#x" in ContextAwareEncoder.encode(raw, ContextType.ATTRIBUTE)
    assert r"\u" in ContextAwareEncoder.encode(raw, ContextType.JAVASCRIPT)
    assert ContextAwareEncoder.encode(raw, ContextType.STYLE) == "<test>"


def test_csp_policy_generator_build_and_nonce() -> None:
    """Verify CSPPolicyGenerator creates standard headers and includes nonces."""
    generator = CSPPolicyGenerator()
    generator.with_nonce("rAnd0mN0nc3")
    generator.add_directive("connect-src", ["https://api.example.com", "'self'"])
    policy = generator.build()

    assert "default-src 'self'" in policy
    assert "'nonce-rAnd0mN0nc3'" in policy
    assert "object-src 'none'" in policy
    assert "connect-src https://api.example.com 'self'" in policy
    assert policy.endswith(";")


def test_csp_policy_audit() -> None:
    """Verify CSP auditor flags dangerous keywords and wildcards."""
    bad_policy = "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval';"
    warnings = CSPPolicyGenerator.audit_policy(bad_policy)
    assert len(warnings) >= 3
    assert any("unsafe-inline" in w for w in warnings)
    assert any("unsafe-eval" in w for w in warnings)
    assert any("object-src" in w for w in warnings)

    good_policy = "default-src 'self'; script-src 'self'; object-src 'none';"
    good_warnings = CSPPolicyGenerator.audit_policy(good_policy)
    assert len(good_warnings) == 0
