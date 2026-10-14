"""
GhostAudit CLI: Terminal interface for automated pipelines and CI/CD security gating.
"""
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from ghostaudit.core.orchestrator import GhostAuditOrchestrator
from ghostaudit.scenarios.data import SCENARIOS

console = Console()


@click.group()
def cli():
    """GhostAudit: Air-Gapped Autonomous Security Forensics powered by Google Gemma."""
    pass


@cli.command()
@click.option("--scenario", default="1_sql_injection_auth_bypass", help="Scenario key from bundled tests")
@click.option("--model", default="gemma2:2b", help="Gemma model variant (Ollama)")
def demo(scenario: str, model: str):
    """Run an instant autonomous forensic triage on a pre-bundled scenario."""
    if scenario not in SCENARIOS:
        console.print(f"[bold red]Scenario '{scenario}' not found. Available: {list(SCENARIOS.keys())}[/bold red]")
        return

    sc = SCENARIOS[scenario]
    console.print(Panel.fit(f"[bold cyan]GhostAudit Autonomous Incident Triage[/bold cyan]\nTarget: {sc['title']}", border_style="cyan"))

    orchestrator = GhostAuditOrchestrator(model_name=model)
    with console.status("[bold green]Executing multi-agent Gemma pipeline...[/bold green]", spinner="dots"):
        report = orchestrator.run_investigation(
            target_name=sc["title"],
            raw_logs=sc["logs"],
            source_code=sc["source"]
        )

    # Display KPI table
    table = Table(title="[bold yellow]Forensics Summary[/bold yellow]")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Incident ID", report.incident_id)
    table.add_row("Gemma Runtime", report.gemma_model_used)
    table.add_row("CVSS Score", f"{report.cerberus.cvss_score} ({report.cerberus.severity.value})")
    table.add_row("CWE Classification", report.cerberus.cwe_id)
    table.add_row("Redacted Secrets (Zero-Trust)", str(report.sanitization_meta.redacted_secrets_count))
    console.print(table)

    console.print(Panel(report.executive_summary, title="[bold green]Executive RCA[/bold green]", border_style="green"))

    console.print("\n[bold yellow]Prometheus Generated Git Patch Diff:[/bold yellow]")
    syntax = Syntax(report.prometheus.git_patch_diff, "diff", theme="monokai", line_numbers=True)
    console.print(syntax)


def main():
    cli()


if __name__ == "__main__":
    main()
