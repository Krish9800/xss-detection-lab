"""Simulation executor for dual-mode vulnerable and hardened XSS endpoints."""

from xsslab.defense.encoder import ContextAwareEncoder
from xsslab.detector.engine import XSSDetectionEngine
from xsslab.lab.storage import StoredXSSStorage
from xsslab.models.audit import LabSimRequest, LabSimResult


class LabSimExecutor:
    """Executes simulated web transactions in insecure (vulnerable) and hardened modes."""

    def __init__(
        self,
        storage: StoredXSSStorage | None = None,
        engine: XSSDetectionEngine | None = None,
    ) -> None:
        self.storage = storage or StoredXSSStorage()
        self.engine = engine or XSSDetectionEngine()

    def simulate(self, request: LabSimRequest) -> LabSimResult:
        """Run a simulated web request against Reflected, Stored, or DOM endpoints.

        Args:
            request: Parameter value, lab mode (insecure/hardened), and lab type.

        Returns:
            LabSimResult containing rendered markup, safety verdict, and audit evaluation.
        """
        verdict = self.engine.analyze(request.param_value)
        lab_type = request.lab_type.lower()
        is_hardened = request.mode.lower() == "hardened"

        if lab_type == "reflected":
            rendered_html, executed_safely = self._simulate_reflected(
                request.param_value, is_hardened, verdict.is_malicious
            )
        elif lab_type == "stored":
            rendered_html, executed_safely = self._simulate_stored(
                request.param_value, is_hardened, verdict.is_malicious
            )
        elif lab_type == "dom":
            rendered_html, executed_safely = self._simulate_dom(
                request.param_value, is_hardened, verdict.is_malicious
            )
        else:
            raise ValueError(
                f"Unknown lab_type '{request.lab_type}'. Expected reflected, stored, or dom."
            )

        return LabSimResult(
            raw_input=request.param_value,
            mode="hardened" if is_hardened else "insecure",
            lab_type=lab_type,
            rendered_html=rendered_html,
            executed_safely=executed_safely,
            audit_verdict=verdict,
        )

    def _simulate_reflected(
        self, param_value: str, is_hardened: bool, is_malicious: bool
    ) -> tuple[str, bool]:
        """Simulate reflected query parameter into HTML template."""
        if is_hardened:
            encoded_value = ContextAwareEncoder.encode_for_html(param_value)
            rendered = f'<div class="greeting">Hello, <span>{encoded_value}</span>!</div>'
            return rendered, True

        rendered = f'<div class="greeting">Hello, <span>{param_value}</span>!</div>'
        return rendered, not is_malicious

    def _simulate_stored(
        self, param_value: str, is_hardened: bool, is_malicious: bool
    ) -> tuple[str, bool]:
        """Simulate stored guestbook comment submission and template rendering."""
        mode_str = "hardened" if is_hardened else "insecure"
        record = self.storage.add_comment(author="Guest", content=param_value, mode=mode_str)
        rendered = (
            f'<div class="comment-card" id="comment-{record["id"]}">'
            f'<h4 class="comment-author">{record["author"]}</h4>'
            f'<p class="comment-body">{record["content"]}</p>'
            "</div>"
        )
        if is_hardened:
            return rendered, True
        return rendered, not is_malicious

    def _simulate_dom(
        self, param_value: str, is_hardened: bool, is_malicious: bool
    ) -> tuple[str, bool]:
        """Simulate dynamic client-side DOM insertion sink."""
        if is_hardened:
            js_encoded = ContextAwareEncoder.encode_for_javascript(param_value)
            rendered = (
                '<div id="dom-view"></div>\n'
                "<script>\n"
                f'  const untrustedInput = "{js_encoded}";\n'
                '  document.getElementById("dom-view").textContent = untrustedInput;\n'
                "</script>"
            )
            return rendered, True

        rendered = (
            '<div id="dom-view"></div>\n'
            "<script>\n"
            f'  const untrustedInput = "{param_value}";\n'
            '  document.getElementById("dom-view").innerHTML = untrustedInput;\n'
            "</script>"
        )
        return rendered, not is_malicious
