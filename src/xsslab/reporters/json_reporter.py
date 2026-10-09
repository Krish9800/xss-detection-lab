"""JSON report generator for xsslab audit results."""

import json
from typing import Any

from xsslab.models.audit import XSSAuditResult
from xsslab.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """Produces structured JSON reports conforming to audit schemas."""

    def generate(self, result: XSSAuditResult) -> str:
        """Render a single audit result to formatted JSON string."""
        data: dict[str, Any] = result.model_dump(mode="json")
        return json.dumps(data, indent=2)

    def generate_batch(self, results: list[XSSAuditResult]) -> str:
        """Render a collection of audit results to a JSON array string."""
        data: list[dict[str, Any]] = [r.model_dump(mode="json") for r in results]
        return json.dumps(data, indent=2)
