"""Command Line Interface for xsslab security audit engine and defensive lab."""

import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from xsslab.config.settings import get_settings
from xsslab.defense.encoder import ContextAwareEncoder
from xsslab.detector.engine import XSSDetectionEngine
from xsslab.lab.endpoints import LabSimExecutor
from xsslab.models.audit import LabSimRequest, XSSAuditResult
from xsslab.models.finding import ContextType
from xsslab.reporters.factory import ReporterFactory

app = typer.Typer(
    name="xsslab",
    help="Enterprise-Grade Cross-Site Scripting (XSS) Detection Engine and Defensive Lab CLI.",
    add_completion=False,
)
console = Console()


def _render_table_audit(result: XSSAuditResult) -> None:
    """Render a single XSSAuditResult as rich terminal tables and panels."""
    badge = (
        "[bold red]MALICIOUS[/]"
        if result.is_malicious
        else (
            "[bold yellow]SUSPICIOUS[/]"
            if result.risk_level == "SUSPICIOUS"
            else "[bold green]CLEAN[/]"
        )
    )

    contexts = ", ".join(c.value for c in result.detected_contexts) or "None"
    info_panel = (
        f"[bold]Verdict:[/] {badge}\n"
        f"[bold]Risk Score:[/] {result.risk_score:.1f}/100.0 ({result.risk_level})\n"
        f"[bold]Detected Contexts:[/] [cyan]{contexts}[/]\n"
        f"[bold]Analyzed At:[/] {result.analyzed_at.isoformat()}"
    )
    console.print(Panel(info_panel, title="XSS Audit Verdict", border_style="blue"))

    if result.sanitized_output:
        console.print(
            Panel(
                result.sanitized_output,
                title="Recommended Sanitized Output",
                border_style="green",
            )
        )

    if result.findings:
        table = Table(title="Detected XSS Triggers", border_style="red")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Rule Name", style="white")
        table.add_column("Category", style="magenta")
        table.add_column("Confidence", style="yellow")
        table.add_column("Matched Snippet", style="red")

        for f in result.findings:
            table.add_row(
                f.finding_id,
                f.rule_name,
                f.category.value,
                f.confidence.value,
                f.matched_payload[:40],
            )
        console.print(table)
    else:
        console.print("[green]✔ No malicious XSS injection patterns detected.[/]")


@app.command(name="audit")
def audit(
    input_text: Annotated[
        str,
        typer.Argument(help="HTML payload or untrusted input parameter to inspect"),
    ],
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, json, markdown, sarif"),
    ] = "table",
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional file path to write results"),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", "-s", help="Exit code 1 on SUSPICIOUS as well as MALICIOUS"),
    ] = False,
) -> None:
    """Audit a single input string for Cross-Site Scripting (XSS) vectors."""
    engine = XSSDetectionEngine()
    result = engine.analyze(input_text)

    if output_format.lower() == "table":
        _render_table_audit(result)
    else:
        try:
            reporter = ReporterFactory.create_reporter(output_format)
            rendered = reporter.generate(result)
            if output_file:
                output_file.write_text(rendered, encoding="utf-8")
                console.print(f"[bold green]Report saved to:[/] {output_file}")
            else:
                typer.echo(rendered)
        except ValueError as err:
            console.print(f"[bold red]Error:[/] {err}")
            raise typer.Exit(code=2) from err

    if result.is_malicious or (strict and result.risk_level == "SUSPICIOUS"):
        raise typer.Exit(code=1)


@app.command(name="analyze")
def analyze(
    file_path: Annotated[
        Path,
        typer.Argument(help="Path to text file containing test payloads line by line"),
    ],
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, json, markdown, sarif"),
    ] = "table",
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional file path to write results"),
    ] = None,
) -> None:
    """Batch analyze test payloads from a file line by line."""
    if not file_path.exists():
        console.print(f"[bold red]Error:[/] File '{file_path}' does not exist.")
        raise typer.Exit(code=2)

    content = file_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip()]

    if not lines:
        console.print("[yellow]Notice:[/] File is empty. Nothing to analyze.")
        return

    engine = XSSDetectionEngine()
    results: list[XSSAuditResult] = [engine.analyze(line) for line in lines]

    if output_format.lower() == "table":
        table = Table(
            title=f"Batch XSS Audit ({len(results)} items)",
            border_style="bright_blue",
        )
        table.add_column("#", justify="right", style="cyan")
        table.add_column("Payload Snippet", style="white")
        table.add_column("Verdict", justify="center")
        table.add_column("Risk Score", justify="right")
        table.add_column("Findings", justify="right")

        for idx, res in enumerate(results, 1):
            snippet = res.input_text.replace("\n", " ")
            if len(snippet) > 45:
                snippet = snippet[:42] + "..."
            status_style = (
                "[bold red]MALICIOUS[/]"
                if res.is_malicious
                else (
                    "[bold yellow]SUSPICIOUS[/]"
                    if res.risk_level == "SUSPICIOUS"
                    else "[bold green]CLEAN[/]"
                )
            )
            table.add_row(
                str(idx),
                snippet,
                status_style,
                f"{res.risk_score:.1f}",
                str(len(res.findings)),
            )

        console.print(table)
    else:
        try:
            reporter = ReporterFactory.create_reporter(output_format)
            rendered = reporter.generate_batch(results)
            if output_file:
                output_file.write_text(rendered, encoding="utf-8")
                console.print(f"[bold green]Batch report saved to:[/] {output_file}")
            else:
                typer.echo(rendered)
        except ValueError as err:
            console.print(f"[bold red]Error:[/] {err}")
            raise typer.Exit(code=2) from err

    if any(r.is_malicious for r in results):
        raise typer.Exit(code=1)


@app.command(name="encode")
def encode(
    input_text: Annotated[
        str,
        typer.Argument(help="Untrusted text to safely encode"),
    ],
    context: Annotated[
        str,
        typer.Option("--context", "-c", help="Target context: html, attr, js, uri, style"),
    ] = "html",
) -> None:
    """Safely encode untrusted input for a specific browser sink context."""
    context_map = {
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

    target_ctx = context_map.get(context.lower().strip())
    if not target_ctx:
        console.print(
            f"[bold red]Error:[/] Unsupported context '{context}'. "
            "Supported: html, attr, js, uri, style"
        )
        raise typer.Exit(code=2)

    encoded = ContextAwareEncoder.encode(input_text, target_ctx)
    console.print(
        Panel(
            f"[bold]Target Context:[/] [cyan]{target_ctx.value}[/]\n"
            f"[bold]Original Input:[/] {input_text}\n"
            f"[bold green]Encoded Output:[/] [white]{encoded}[/]",
            title="Context-Aware Safe Encoding",
            border_style="green",
        )
    )


@app.command(name="benchmark")
def benchmark() -> None:
    """Run built-in benchmark against known XSS vectors and benign inputs."""
    malicious_corpus = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert(1)>",
        '<iframe src="javascript:alert(1)"></iframe>',
        "javascript:alert(1)",
        "';alert(1);//",
        "<body onload=alert(1)>",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        '<input type="text" value="" onfocus="alert(1)" autofocus>',
        '<a href="javascript:alert(1)">Click me</a>',
    ]

    benign_corpus = [
        "Hello, World!",
        "user_profile_id=12345",
        "https://example.com/search?q=cybersecurity",
        "Alice & Bob went to the market",
        "Please select: Option A > Option B",
        "<p>Standard formatted paragraph text</p>",
        "contact@domain.com",
        "Price: $19.99 for 2 items",
        "Coordinates: 37.7749,-122.4194",
        "John Doe - Senior Security Architect",
    ]

    engine = XSSDetectionEngine()
    start_time = time.perf_counter()

    tp = sum(1 for p in malicious_corpus if engine.analyze(p).is_malicious)
    fn = len(malicious_corpus) - tp

    fp = sum(1 for p in benign_corpus if engine.analyze(p).is_malicious)
    tn = len(benign_corpus) - fp

    elapsed = (time.perf_counter() - start_time) * 1000
    total = len(malicious_corpus) + len(benign_corpus)
    avg_latency = elapsed / total

    accuracy = (tp + tn) / total * 100.0
    precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0

    table = Table(title="XSS Detection Engine Benchmark Results", border_style="green")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Total Evaluated Payloads", str(total))
    table.add_row("True Positives (TP)", f"[green]{tp}[/]")
    table.add_row("True Negatives (TN)", f"[green]{tn}[/]")
    table.add_row("False Positives (FP)", f"[red]{fp}[/]" if fp > 0 else "0")
    table.add_row("False Negatives (FN)", f"[red]{fn}[/]" if fn > 0 else "0")
    table.add_row("Accuracy", f"{accuracy:.1f}%")
    table.add_row("Precision", f"{precision:.1f}%")
    table.add_row("Recall (TPR)", f"{recall:.1f}%")
    table.add_row("Average Latency", f"{avg_latency:.2f} ms/payload")

    console.print(table)


@app.command(name="lab")
def lab(
    param_value: Annotated[
        str,
        typer.Argument(help="Untrusted parameter value to inject into simulated endpoint"),
    ],
    mode: Annotated[
        str,
        typer.Option("--mode", "-m", help="Execution mode: insecure or hardened"),
    ] = "insecure",
    lab_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Target lab: reflected, stored, or dom"),
    ] = "reflected",
) -> None:
    """Execute simulated XSS payload in vulnerable or hardened simulation lab."""
    executor = LabSimExecutor()
    req = LabSimRequest(param_value=param_value, mode=mode, lab_type=lab_type)
    try:
        res = executor.simulate(req)
    except ValueError as err:
        console.print(f"[bold red]Error:[/] {err}")
        raise typer.Exit(code=2) from err

    safety_badge = (
        "[bold green]SAFE (Neutralized)[/]"
        if res.executed_safely
        else "[bold red]VULNERABLE (Executed)[/]"
    )
    console.print(
        Panel(
            f"[bold]Target Lab:[/] {res.lab_type.upper()}\n"
            f"[bold]Execution Mode:[/] {res.mode.upper()}\n"
            f"[bold]Safety Status:[/] {safety_badge}\n\n"
            f"[bold]Rendered Markup / Sink Code:[/] \n[cyan]{res.rendered_html}[/]",
            title="Defensive Lab Execution Result",
            border_style="green" if res.executed_safely else "red",
        )
    )
    if not res.executed_safely:
        raise typer.Exit(code=1)


@app.command(name="version")
def version() -> None:
    """Display xsslab tool version and configuration details."""
    settings = get_settings()
    console.print(
        Panel(
            f"[bold cyan]xsslab[/] Cross-Site Scripting Detection Lab\n"
            f"[bold]Version:[/] {settings.version}\n"
            f"[bold]Environment:[/] {settings.environment}\n"
            f"[bold]Strict Script Blocking:[/] {settings.strict_script_blocking}\n"
            f"[bold]Decode Entities Before Scan:[/] {settings.decode_entities_before_scan}",
            title="System Information",
            border_style="blue",
        )
    )


if __name__ == "__main__":
    app()
