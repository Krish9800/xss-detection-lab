"""Markdown report generator for xsslab security audit results."""

from xsslab.models.audit import XSSAuditResult
from xsslab.reporters.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Produces GitHub Flavored Markdown security audit reports."""

    def generate(self, result: XSSAuditResult) -> str:
        """Render a single audit result to a formatted Markdown report."""
        badge = (
            "🔴 **CRITICAL / MALICIOUS**"
            if result.is_malicious
            else (
                "🟡 **SUSPICIOUS**"
                if result.risk_level == "SUSPICIOUS"
                else "🟢 **CLEAN / BENIGN**"
            )
        )

        contexts_str = ", ".join(f"`{c.value}`" for c in result.detected_contexts) or "None"

        md_lines = [
            "# XSS Security Audit Report",
            "",
            f"**Audit Verdict:** {badge}  ",
            f"**Risk Score:** `{result.risk_score:.1f}/100.0` ({result.risk_level})  ",
            f"**Target Contexts:** {contexts_str}  ",
            f"**Analyzed At:** `{result.analyzed_at.isoformat()}`  ",
            "",
            "## Inspected Payload",
            "```html",
            result.input_text,
            "```",
            "",
        ]

        if result.sanitized_output:
            md_lines.extend(
                [
                    "## Recommended Sanitized Output",
                    "```html",
                    result.sanitized_output,
                    "```",
                    "",
                ]
            )

        md_lines.append("## Findings Summary")

        if not result.findings:
            md_lines.extend(
                [
                    "",
                    "> No cross-site scripting patterns, dangerous event handlers, or obfuscations detected.",
                    "",
                ]
            )
        else:
            md_lines.extend(
                [
                    "",
                    "| ID | Rule Name | Category | Confidence | Matched Payload |",
                    "| :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for f in result.findings:
                escaped_match = f.matched_payload.replace("|", "\\|").replace("\n", " ")
                md_lines.append(
                    f"| `{f.finding_id}` | {f.rule_name} | `{f.category.value}` "
                    f"| `{f.confidence.value}` | `{escaped_match}` |"
                )

            md_lines.extend(
                [
                    "",
                    "## Technical Explanations & Remediation",
                    "",
                ]
            )
            for f in result.findings:
                md_lines.extend(
                    [
                        f"### {f.rule_name} (`{f.finding_id}`)",
                        f"- **Explanation:** {f.explanation}",
                        f"- **Remediation:** {f.remediation}",
                        "",
                    ]
                )

        md_lines.extend(
            [
                "---",
                "*Generated automatically by XSS-Detection-Lab Security Auditor.*",
            ]
        )
        return "\n".join(md_lines)

    def generate_batch(self, results: list[XSSAuditResult]) -> str:
        """Render multiple audit results into a consolidated Markdown document."""
        md_lines = [
            "# Batch XSS Security Audit Report",
            "",
            f"**Total Payloads Audited:** `{len(results)}`  ",
            f"**Malicious Payloads Detected:** `{sum(1 for r in results if r.is_malicious)}`  ",
            "",
            "| # | Payload Snippet | Verdict | Risk Score | Findings |",
            "| :- | :--- | :--- | :--- | :--- |",
        ]

        for i, r in enumerate(results, 1):
            snippet = r.input_text.replace("\n", " ")
            if len(snippet) > 40:
                snippet = snippet[:37] + "..."
            snippet = snippet.replace("|", "\\|")
            if r.is_malicious:
                status_icon = "🔴"
            elif r.risk_level == "SUSPICIOUS":
                status_icon = "🟡"
            else:
                status_icon = "🟢"

            md_lines.append(
                f"| {i} | `{snippet}` | {status_icon} `{r.risk_level}` "
                f"| `{r.risk_score:.1f}` | `{len(r.findings)}` |"
            )

        md_lines.extend(
            [
                "",
                "---",
                "*Generated automatically by XSS-Detection-Lab Security Auditor.*",
            ]
        )
        return "\n".join(md_lines)
