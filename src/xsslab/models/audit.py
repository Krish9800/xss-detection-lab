"""Domain models representing audit verdicts, encoding operations, and lab requests."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from xsslab.models.finding import ContextType, DetectionFinding


class XSSAuditResult(BaseModel):
    """Consolidated assessment verdict for an inspected input string."""

    input_text: str = Field(..., description="Original input text analyzed")
    is_malicious: bool = Field(..., description="True if assessed as malicious XSS attack")
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated risk score from 0.0 to 100.0",
    )
    risk_level: str = Field(
        default="CLEAN",
        description="Qualitative risk classification: CLEAN, SUSPICIOUS, or MALICIOUS",
    )
    detected_contexts: list[ContextType] = Field(
        default_factory=list,
        description="Browser contexts targeted or present in payload",
    )
    findings: list[DetectionFinding] = Field(
        default_factory=list,
        description="List of specific detection triggers",
    )
    sanitized_output: str | None = Field(
        default=None,
        description="Recommended context-encoded representation",
    )
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC analysis timestamp",
    )


class EncodingRequest(BaseModel):
    """Request to safely encode an untrusted input string for a specific context."""

    input_text: str = Field(..., description="Raw untrusted input text")
    context: ContextType = Field(
        default=ContextType.HTML_BODY,
        description="Target browser document context",
    )


class EncodingResult(BaseModel):
    """Result of context-aware safe encoding."""

    original_text: str
    context: ContextType
    encoded_text: str


class LabSimRequest(BaseModel):
    """Request to test input within the simulated web application lab."""

    param_value: str = Field(..., description="Untrusted parameter value to inject")
    mode: str = Field(
        default="insecure",
        description="Execution mode: 'insecure' (raw reflection) or 'hardened' (context-encoded)",
    )
    lab_type: str = Field(
        default="reflected",
        description="Lab type: 'reflected', 'stored', or 'dom'",
    )


class LabSimResult(BaseModel):
    """Result of simulated execution in vulnerable or hardened modes."""

    raw_input: str
    mode: str
    lab_type: str
    rendered_html: str
    executed_safely: bool
    audit_verdict: XSSAuditResult | None = None
