"""Content Security Policy (CSP) generator and audit validator."""

from typing import Self


class CSPPolicyGenerator:
    """Constructs strict Content-Security-Policy headers and audits policies for weaknesses."""

    def __init__(self) -> None:
        """Initialize with strict default directives."""
        self.directives: dict[str, list[str]] = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "object-src": ["'none'"],
            "base-uri": ["'self'"],
            "frame-ancestors": ["'none'"],
            "form-action": ["'self'"],
        }

    def with_nonce(self, nonce: str) -> Self:
        """Add cryptographic script nonce for dynamic inline script authorization."""
        script_sources = self.directives.setdefault("script-src", ["'self'"])
        nonce_directive = f"'nonce-{nonce}'"
        if nonce_directive not in script_sources:
            script_sources.append(nonce_directive)
        return self

    def add_directive(self, directive: str, sources: list[str]) -> Self:
        """Add or append sources to a specific policy directive."""
        existing = self.directives.setdefault(directive, [])
        for src in sources:
            if src not in existing:
                existing.append(src)
        return self

    def build(self) -> str:
        """Compile configured directives into a standard CSP header string."""
        parts: list[str] = []
        for directive, sources in self.directives.items():
            sources_str = " ".join(sources)
            parts.append(f"{directive} {sources_str}")
        return "; ".join(parts) + ";"

    @classmethod
    def audit_policy(cls, policy_str: str) -> list[str]:
        """Audit a CSP header string and flag dangerous or insecure directives.

        Args:
            policy_str: Raw CSP header value string.

        Returns:
            List of warning messages identifying security weaknesses.
        """
        warnings: list[str] = []
        lower = policy_str.lower()

        if "'unsafe-inline'" in lower:
            warnings.append(
                "Policy includes \"'unsafe-inline'\", enabling execution of injected inline scripts."
            )

        if "'unsafe-eval'" in lower:
            warnings.append(
                "Policy includes \"'unsafe-eval'\", enabling string-to-code execution sinks."
            )

        if "object-src 'none'" not in lower and "default-src 'none'" not in lower:
            warnings.append(
                "Policy missing \"object-src 'none'\", allowing malicious plugin object injection."
            )

        if "default-src *" in lower or "script-src *" in lower:
            warnings.append(
                "Policy uses wildcard '*' source, allowing script loading from arbitrary origins."
            )

        return warnings
