"""Pydantic schemas for the xsslab REST API microservice."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from xsslab.models.audit import EncodingResult, LabSimResult, XSSAuditResult


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="healthy", description="Service health state")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Current server UTC timestamp",
    )


class DetectRequest(BaseModel):
    """Request payload to inspect input string for XSS vectors."""

    input_text: str = Field(..., min_length=1, description="Untrusted payload or HTML to inspect")


class SanitizeRequest(BaseModel):
    """Request payload to contextually encode untrusted input."""

    input_text: str = Field(..., description="Raw text to encode")
    context: str = Field(default="html", description="Target context: html, attr, js, uri, style")


class CSPAuditRequest(BaseModel):
    """Request payload to audit a Content Security Policy string."""

    policy: str = Field(..., min_length=1, description="CSP header string to audit")


class CSPAuditResponse(BaseModel):
    """Result of Content Security Policy analysis."""

    policy: str
    is_safe: bool
    warnings: list[str]


class RuleDetail(BaseModel):
    """Metadata describing an active detection signature rule."""

    rule_id: str
    name: str
    category: str
    context: str
    confidence: str
    cwe_id: str
    explanation: str
    remediation: str


class RulesListResponse(BaseModel):
    """Response containing all registered detection rules."""

    total_rules: int
    rules: list[RuleDetail]


__all__ = [
    "CSPAuditRequest",
    "CSPAuditResponse",
    "DetectRequest",
    "EncodingResult",
    "HealthResponse",
    "LabSimResult",
    "RuleDetail",
    "RulesListResponse",
    "SanitizeRequest",
    "XSSAuditResult",
]
