"""Context-aware output encoding engine for neutralizing XSS injection vectors."""

import urllib.parse
from html import escape
from typing import ClassVar

from xsslab.models.finding import ContextType


class ContextAwareEncoder:
    """Provides context-specific encoding and sanitization for diverse browser sinks."""

    DANGEROUS_SCHEMES: ClassVar[set[str]] = {"javascript", "vbscript", "data", "file"}

    @classmethod
    def encode(cls, text: str, context: ContextType = ContextType.HTML_BODY) -> str:
        """Encode untrusted input string according to the target browser context.

        Args:
            text: Raw untrusted input string.
            context: Target ContextType (HTML_BODY, ATTRIBUTE, JAVASCRIPT, URI, STYLE).

        Returns:
            Safely encoded string representation.
        """
        if context == ContextType.HTML_BODY:
            return cls.encode_for_html(text)
        if context == ContextType.ATTRIBUTE:
            return cls.encode_for_attribute(text)
        if context == ContextType.JAVASCRIPT:
            return cls.encode_for_javascript(text)
        if context == ContextType.URI:
            return cls.encode_for_uri(text)
        if context == ContextType.STYLE:
            return cls.encode_for_style(text)
        return cls.encode_for_html(text)

    @classmethod
    def encode_for_html(cls, text: str) -> str:
        """Encode characters for safe insertion into HTML body elements."""
        encoded = escape(text, quote=True)
        # Explicitly encode forward slash and single quote
        return encoded.replace("/", "&#x2F;").replace("'", "&#x27;")

    @classmethod
    def encode_for_attribute(cls, text: str) -> str:
        """Encode non-alphanumeric ASCII characters into hexadecimal entities for attributes."""
        encoded_chars: list[str] = []
        for char in text:
            if char.isalnum() or char in ("-", "_", "."):
                encoded_chars.append(char)
            else:
                hex_val = hex(ord(char))[2:].upper().zfill(2)
                encoded_chars.append(f"&#x{hex_val};")
        return "".join(encoded_chars)

    @classmethod
    def encode_for_javascript(cls, text: str) -> str:
        """Encode non-alphanumeric characters into Unicode escape sequences for script strings."""
        encoded_chars: list[str] = []
        for char in text:
            if char.isalnum() or char in (" ", "-", "_"):
                encoded_chars.append(char)
            else:
                hex_val = hex(ord(char))[2:].upper().zfill(4)
                encoded_chars.append(f"\\u{hex_val}")
        return "".join(encoded_chars)

    @classmethod
    def encode_for_uri(cls, text: str) -> str:
        """Validate URI scheme and percent-encode unsafe URL parameters."""
        stripped = text.strip()
        parsed = urllib.parse.urlparse(stripped)

        if parsed.scheme.lower() in cls.DANGEROUS_SCHEMES:
            # Block executable pseudo-protocols
            return "about:blank"

        return urllib.parse.quote(stripped, safe="/?=&:#-._~%")

    @classmethod
    def encode_for_style(cls, text: str) -> str:
        """Sanitize CSS content to neutralize expression() and URL breakouts."""
        return re_style_cleanup(text)


def re_style_cleanup(text: str) -> str:
    """Remove dangerous CSS expressions and javascript: URL wrappers."""
    cleaned = text.replace("expression", "blocked_expr")
    cleaned = cleaned.replace("javascript:", "blocked_js:")
    return cleaned.replace("vbscript:", "blocked_vbs:")
