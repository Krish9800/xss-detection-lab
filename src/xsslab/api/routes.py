"""API route handlers for xsslab detection, defense, and simulation lab."""

from fastapi import APIRouter, HTTPException, status

from xsslab.api.schemas import (
    CSPAuditRequest,
    CSPAuditResponse,
    DetectRequest,
    HealthResponse,
    RuleDetail,
    RulesListResponse,
    SanitizeRequest,
)
from xsslab.config.settings import get_settings
from xsslab.defense.csp import CSPPolicyGenerator
from xsslab.defense.encoder import ContextAwareEncoder
from xsslab.detector.engine import XSSDetectionEngine
from xsslab.detector.signatures import XSSSignatureEngine
from xsslab.lab.endpoints import LabSimExecutor
from xsslab.models.audit import EncodingResult, LabSimRequest, LabSimResult, XSSAuditResult
from xsslab.models.finding import ContextType

router = APIRouter()
_detector = XSSDetectionEngine()
_lab_executor = LabSimExecutor(engine=_detector)

_CONTEXT_MAP: dict[str, ContextType] = {
    "html": ContextType.HTML_BODY,
    "attr": ContextType.ATTRIBUTE,
    "attribute": ContextType.ATTRIBUTE,
    "js": ContextType.JAVASCRIPT,
    "javascript": ContextType.JAVASCRIPT,
    "uri": ContextType.URI,
    "url": ContextType.URI,
    "style": ContextType.STYLE,
    "css": ContextType.STYLE,
}


@router.get("/health", response_model=HealthResponse, tags=["System"])
def get_health() -> HealthResponse:
    """Return microservice health status and application version."""
    settings = get_settings()
    return HealthResponse(status="healthy", version=settings.version)


@router.post(
    "/api/v1/detect",
    response_model=XSSAuditResult,
    status_code=status.HTTP_200_OK,
    tags=["Detection"],
)
def detect_xss(payload: DetectRequest) -> XSSAuditResult:
    """Inspect input string for Cross-Site Scripting patterns and risk score."""
    return _detector.analyze(payload.input_text)


@router.post(
    "/api/v1/sanitize",
    response_model=EncodingResult,
    status_code=status.HTTP_200_OK,
    tags=["Defense"],
)
def sanitize_input(payload: SanitizeRequest) -> EncodingResult:
    """Contextually encode untrusted input to neutralize execution in target sink."""
    target_ctx = _CONTEXT_MAP.get(payload.context.lower().strip())
    if not target_ctx:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported context '{payload.context}'. Supported: html, attr, js, uri, style."
            ),
        )
    encoded = ContextAwareEncoder.encode(payload.input_text, target_ctx)
    return EncodingResult(
        original_text=payload.input_text,
        context=target_ctx,
        encoded_text=encoded,
    )


@router.post(
    "/api/v1/simulate",
    response_model=LabSimResult,
    status_code=status.HTTP_200_OK,
    tags=["Simulation Lab"],
)
def simulate_xss(payload: LabSimRequest) -> LabSimResult:
    """Simulate execution of input in vulnerable or hardened reflected/stored/DOM lab."""
    try:
        return _lab_executor.simulate(payload)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err


@router.post(
    "/api/v1/audit/csp",
    response_model=CSPAuditResponse,
    status_code=status.HTTP_200_OK,
    tags=["Defense"],
)
def audit_csp(payload: CSPAuditRequest) -> CSPAuditResponse:
    """Audit Content Security Policy header for bypasses and unsafe directives."""
    warnings = CSPPolicyGenerator.audit_policy(payload.policy)
    return CSPAuditResponse(
        policy=payload.policy,
        is_safe=len(warnings) == 0,
        warnings=warnings,
    )


@router.get(
    "/api/v1/rules",
    response_model=RulesListResponse,
    tags=["Taxonomy"],
)
def list_rules() -> RulesListResponse:
    """List all registered XSS signature rules with CWE taxonomy and remediation guidance."""
    rule_details = [
        RuleDetail(
            rule_id=r.rule_id,
            name=r.name,
            category=r.category.value,
            context=r.context.value,
            confidence=r.confidence.value,
            cwe_id="CWE-79",
            explanation=r.explanation,
            remediation=r.remediation,
        )
        for r in XSSSignatureEngine.RULES
    ]
    return RulesListResponse(total_rules=len(rule_details), rules=rule_details)
