"""SARIF (OASIS Static Analysis Results Interchange Format v2.1.0) reporter for xsslab."""

import json
from typing import Any

from xsslab.models.audit import XSSAuditResult
from xsslab.models.finding import ConfidenceLevel, DetectionFinding
from xsslab.reporters.base import BaseReporter


class SARIFReporter(BaseReporter):
    """Produces OASIS SARIF v2.1.0 schema reports for GitHub Code Scanning."""

    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def generate(self, result: XSSAuditResult) -> str:
        """Render a single XSSAuditResult as a SARIF v2.1.0 JSON string."""
        return self.generate_batch([result])

    def generate_batch(self, results: list[XSSAuditResult]) -> str:
        """Render multiple XSSAuditResults into a unified SARIF v2.1.0 report."""
        rules_map: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for result in results:
            for finding in result.findings:
                if finding.finding_id not in rules_map:
                    rules_map[finding.finding_id] = self._create_sarif_rule(finding)

                sarif_results.append(self._create_sarif_result(finding, result.input_text))

        sarif_document = {
            "$schema": self.SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "xsslab",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/cybersecurity-portfolio/xss-detection-lab",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        return json.dumps(sarif_document, indent=2)

    def _create_sarif_rule(self, finding: DetectionFinding) -> dict[str, Any]:
        """Convert a detection finding into a SARIF rule definition."""
        level = self._map_confidence_to_sarif_level(finding.confidence)
        return {
            "id": finding.finding_id,
            "name": finding.rule_name,
            "shortDescription": {"text": finding.rule_name},
            "fullDescription": {"text": finding.explanation},
            "defaultConfiguration": {"level": level},
            "help": {
                "text": f"Remediation: {finding.remediation}",
                "markdown": f"### Remediation\n\n{finding.remediation}",
            },
            "properties": {
                "category": finding.category.value,
                "cwe": finding.cwe_id,
            },
        }

    def _create_sarif_result(
        self,
        finding: DetectionFinding,
        input_text: str,
    ) -> dict[str, Any]:
        """Convert a detection finding match into a SARIF result item."""
        level = self._map_confidence_to_sarif_level(finding.confidence)
        return {
            "ruleId": finding.finding_id,
            "level": level,
            "message": {
                "text": (
                    f"Cross-Site Scripting detected: {finding.explanation} "
                    f"(Matched: {finding.matched_payload})"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "payload_input.html"},
                        "region": {
                            "startLine": 1,
                            "snippet": {"text": input_text[:120]},
                        },
                    }
                }
            ],
        }

    def _map_confidence_to_sarif_level(self, confidence: ConfidenceLevel) -> str:
        """Map detection confidence to SARIF severity level."""
        if confidence in (ConfidenceLevel.CERTAIN, ConfidenceLevel.HIGH):
            return "error"
        if confidence == ConfidenceLevel.MEDIUM:
            return "warning"
        return "note"
