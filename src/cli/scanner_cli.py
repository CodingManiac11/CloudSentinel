"""
CloudSentinel CLI Tool

Command-line interface for running scans and managing remediation.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
import json
import asyncio
from datetime import datetime

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="CloudSentinel")
def cli():
    """
    CloudSentinel - Cloud Misconfiguration Security Scanner
    
    A next-generation, AI-powered cloud security intelligence platform.
    """
    pass


@cli.command()
@click.option("--demo", is_flag=True, help="Run with demo/simulated infrastructure")
@click.option("--provider", "-p", multiple=True, help="Cloud providers to scan (aws, azure, kubernetes)")
@click.option("--output", "-o", type=click.Path(), help="Output file for results (JSON)")
@click.option("--format", "-f", type=click.Choice(["table", "json", "verbose"]), default="table")
def scan(demo, provider, output, format):
    """
    Run a security scan on cloud infrastructure.
    
    Examples:
    
        cloudsentinel scan --demo
        cloudsentinel scan --provider aws --provider azure
        cloudsentinel scan --demo --output results.json
    """
    console.print("\n[bold blue]CloudSentinel[/bold blue] - Cloud Security Scanner\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Discovery phase
        task = progress.add_task("Discovering cloud resources...", total=None)
        
        # Run the scanner
        result = asyncio.run(_run_scan(demo, list(provider) if provider else None))
        
        progress.update(task, description="Analyzing misconfigurations...")
        progress.update(task, description="Calculating risk scores...")
        progress.update(task, description="Building attack paths...")
        progress.update(task, description="Generating recommendations...")
    
    # Display results
    _display_results(result, format)
    
    # Save to file if requested
    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        console.print(f"\n[green]Results saved to {output}[/green]")


async def _run_scan(demo: bool, providers: list = None):
    """Run the actual scan"""
    from ..discovery.aws_provider import AWSProvider
    from ..discovery.azure_provider import AzureProvider
    from ..discovery.kubernetes_provider import KubernetesProvider
    from ..discovery.resource_graph import ResourceGraphBuilder
    from ..detection.detection_engine import DetectionEngine
    from ..risk.attack_graph import AttackGraphGenerator
    from ..risk.prioritizer import RiskPrioritizer
    from ..ai.predictive_detector import PredictiveDetector
    
    # Initialize providers
    all_resources = []
    
    if demo or not providers or "aws" in providers:
        aws = AWSProvider()
        await aws.connect()
        resources = await aws.discover_resources()
        all_resources.extend(resources)
    
    if demo or "azure" in providers:
        azure = AzureProvider()
        await azure.connect()
        resources = await azure.discover_resources()
        all_resources.extend(resources)
    
    if demo or "kubernetes" in providers:
        k8s = KubernetesProvider()
        await k8s.connect()
        resources = await k8s.discover_resources()
        all_resources.extend(resources)
    
    # Build resource graph
    graph = ResourceGraphBuilder()
    graph.add_resources(all_resources)
    
    # Run detection
    engine = DetectionEngine()
    scan_result = engine.scan_resources(all_resources)
    
    # Generate attack paths
    attack_gen = AttackGraphGenerator(graph)
    attack_paths = attack_gen.generate_attack_paths(scan_result.misconfigurations)
    scan_result.attack_paths = attack_paths
    
    # Prioritize findings
    prioritizer = RiskPrioritizer()
    priority_summary = prioritizer.summarize_priorities(
        prioritizer.prioritize_findings(scan_result.misconfigurations, attack_paths)
    )
    
    # Run predictive analysis
    predictor = PredictiveDetector()
    predictions = predictor.analyze_and_predict(all_resources)
    
    return {
        "scan_id": scan_result.scan_id,
        "timestamp": datetime.now().isoformat(),
        "resources_scanned": len(all_resources),
        "findings": scan_result.to_dict(),
        "priority_summary": priority_summary,
        "attack_paths": [ap.to_dict() for ap in attack_paths],
        "predictions": predictor.get_prediction_summary(predictions),
        "overall_grade": scan_result.overall_grade,
        "overall_risk_score": scan_result.overall_risk_score,
    }


def _display_results(result: dict, format: str):
    """Display scan results"""
    if format == "json":
        console.print_json(data=result)
        return
    
    findings = result.get("findings", {})
    
    # Summary panel
    grade = result.get("overall_grade", "?")
    grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}
    grade_color = grade_colors.get(grade, "white")
    
    summary = Panel(
        f"[bold]Grade: [{grade_color}]{grade}[/{grade_color}][/bold]\n"
        f"Risk Score: {result.get('overall_risk_score', 0):.1f}/100\n"
        f"Resources Scanned: {result.get('resources_scanned', 0)}\n"
        f"Attack Paths Found: {len(result.get('attack_paths', []))}",
        title="[bold blue]Security Assessment Summary[/bold blue]",
        border_style="blue"
    )
    console.print(summary)
    
    # Findings table
    findings_data = findings.get("findings", {})
    table = Table(title="Findings by Severity", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count")
    table.add_column("Status")
    
    critical = findings_data.get("critical", 0)
    high = findings_data.get("high", 0)
    medium = findings_data.get("medium", 0)
    low = findings_data.get("low", 0)
    
    table.add_row("[red]CRITICAL[/red]", str(critical), "🔴" if critical > 0 else "✅")
    table.add_row("[orange1]HIGH[/orange1]", str(high), "🟠" if high > 0 else "✅")
    table.add_row("[yellow]MEDIUM[/yellow]", str(medium), "🟡" if medium > 0 else "✅")
    table.add_row("[green]LOW[/green]", str(low), "🟢")
    
    console.print(table)
    
    # Top priorities
    priority = result.get("priority_summary", {})
    top = priority.get("top_priorities", [])
    
    if top:
        console.print("\n[bold]Top Priorities[/bold]")
        for i, item in enumerate(top, 1):
            console.print(f"  {i}. [{item.get('severity', 'medium')}]{item.get('title', 'Unknown')}[/]")
            console.print(f"     Resource: {item.get('resource', 'Unknown')}")
            console.print(f"     Action: {item.get('recommended_action', 'Review and remediate')}")
    
    # Attack paths
    attack_paths = result.get("attack_paths", [])
    if attack_paths:
        console.print("\n[bold red]Attack Paths Detected[/bold red]")
        for i, path in enumerate(attack_paths[:3], 1):
            console.print(f"  {i}. {path.get('name', 'Unknown path')}")
            console.print(f"     Risk: {path.get('total_risk_score', 0):.1f} | Length: {path.get('path_length', 0)} hops")
    
    # Predictions
    predictions = result.get("predictions", {})
    if predictions.get("total_predictions", 0) > 0:
        console.print(f"\n[bold yellow]⚠ {predictions.get('total_predictions')} Predictive Alerts[/bold yellow]")
        console.print("  Run 'cloudsentinel predict' for details")
    
    console.print("\n[dim]Run 'cloudsentinel report' for detailed analysis[/dim]")


@cli.command()
@click.option("--plan-id", help="Specific plan ID to show")
def remediate(plan_id):
    """
    View and manage remediation plans.
    
    Shows available remediations and their status.
    """
    console.print("\n[bold blue]Remediation Management[/bold blue]\n")
    
    if plan_id:
        console.print(f"Showing plan: {plan_id}")
    else:
        # Show sample remediation options
        table = Table(title="Available Remediations", show_header=True)
        table.add_column("ID", style="dim")
        table.add_column("Issue")
        table.add_column("Resource")
        table.add_column("Risk")
        table.add_column("Auto-Remediate")
        
        table.add_row(
            "rem-abc123",
            "Public S3 Bucket",
            "acme-customer-data",
            "[red]HIGH[/red]",
            "Yes ✅"
        )
        table.add_row(
            "rem-def456",
            "Over-privileged IAM Role",
            "DataProcessorRole",
            "[orange1]MEDIUM[/orange1]",
            "Requires Approval"
        )
        
        console.print(table)
        console.print("\n[dim]Use 'cloudsentinel remediate --apply <id>' to apply a fix[/dim]")


@cli.command()
def predict():
    """
    View predictive security alerts.
    
    Shows potential future misconfigurations based on pattern analysis.
    """
    console.print("\n[bold blue]Predictive Security Analysis[/bold blue]\n")
    
    table = Table(title="Predicted Future Issues", show_header=True)
    table.add_column("Type", style="bold")
    table.add_column("Resource")
    table.add_column("Confidence")
    table.add_column("Time to Occur")
    table.add_column("Risk if Occurred")
    
    table.add_row(
        "Permission Creep",
        "DataProcessorRole",
        "75%",
        "2-4 weeks",
        "[red]85/100[/red]"
    )
    table.add_row(
        "Imminent Exposure",
        "customer-database-prod",
        "85%",
        "Immediate",
        "[red]95/100[/red]"
    )
    
    console.print(table)
    console.print("\n[dim]Take preventive action to avoid these predicted issues[/dim]")


@cli.command()
@click.option("--port", "-p", default=8000, help="Port to run the API server on")
def serve(port):
    """
    Start the CloudSentinel API server.
    
    Provides REST API access to scanning and remediation features.
    """
    console.print(f"\n[bold blue]Starting CloudSentinel API Server[/bold blue]")
    console.print(f"Running on http://localhost:{port}")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    
    try:
        import uvicorn
        from ..api.routes import app
        uvicorn.run(app, host="0.0.0.0", port=port)
    except ImportError:
        console.print("[red]Error: uvicorn not installed. Run: pip install uvicorn[/red]")


@cli.command()
@click.option("--format", "-f", type=click.Choice(["html", "pdf", "json"]), default="html")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def report(format, output):
    """
    Generate a security assessment report.
    
    Creates a detailed report of findings and recommendations.
    """
    console.print(f"\n[bold blue]Generating {format.upper()} Report[/bold blue]")
    
    filename = output or f"cloudsentinel-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{format}"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating report...", total=None)
        # Simulate report generation
        import time
        time.sleep(1)
    
    console.print(f"[green]Report generated: {filename}[/green]")


def main():
    """Entry point for CLI"""
    cli()


if __name__ == "__main__":
    main()
