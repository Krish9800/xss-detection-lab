"""Domain models representing XSS taxonomy, execution contexts, and findings."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class XSSCategory(StrEnum):
    """Classification of XSS vector categories."""

    REFLECTED = "REFLECTED"
    STORED = "STORED"
    DOM_BASED = "DOM_BASED"
    ATTRIBUTE_INJECTION = "ATTRIBUTE_INJECTION"
    SCRIPT_GADGET = "SCRIPT_GADGET"
    PROTOCOL_HANDLER = "PROTOCOL_HANDLER"
    HTML_TAG_INJECTION = "HTML_TAG_INJECTION"
    EVENT_HANDLER = "EVENT_HANDLER"
    HEURISTIC_ANOMALY = "HEURISTIC_ANOMALY"


class ContextType(StrEnum):
    """Target browser document execution contexts."""

    HTML_BODY = "HTML_BODY"
    ATTRIBUTE = "ATTRIBUTE"
    JAVASCRIPT = "JAVASCRIPT"
    URI = "URI"
    STYLE = "STYLE"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(StrEnum):
    """Detection confidence rating."""

    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class DetectionFinding(BaseModel):
    """Individual XSS detection trigger or contextual anomaly finding."""

    finding_id: str = Field(..., description="Unique finding or rule identifier")
    rule_name: str = Field(..., description="Human-readable rule name")
    category: XSSCategory = Field(..., description="Vulnerability vector category")
    context: ContextType = Field(
        default=ContextType.UNKNOWN,
        description="Target browser execution context",
    )
    confidence: ConfidenceLevel = Field(..., description="Detection confidence level")
    cwe_id: str = Field(default="CWE-79", description="Mitre CWE identifier (CWE-79)")
    matched_payload: str = Field(..., description="Substring or pattern triggering the rule")
    explanation: str = Field(..., description="Technical explanation of the detected flaw")
    remediation: str = Field(
        default="Apply context-appropriate output encoding and strict Content Security Policy.",
        description="Actionable mitigation guidance",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional lexical metadata or token details",
    )
