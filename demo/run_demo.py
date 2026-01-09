#!/usr/bin/env python3
"""
CloudSentinel Demo Script

Demonstrates the full capabilities of CloudSentinel security scanner.
"""

import asyncio
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

console = Console()


def print_header():
    """Print demo header"""
    console.print(Panel.fit(
        "[bold blue]CloudSentinel[/bold blue]\n"
        "[dim]Next-Generation Cloud Security Scanner[/dim]\n\n"
        "🛡️ Attack-Graph-Driven Prioritization\n"
        "🔮 Predictive Misconfiguration Detection\n"
        "🔍 AI-Assisted Root Cause Analysis\n"
        "🤖 Autonomous Remediation with Guardrails\n"
        "🌐 Cross-Cloud Risk Normalization",
        title="[bold]Demo[/bold]",
        border_style="blue"
    ))


async def run_demo():
    """Run the complete demo"""
    import sys
    sys.path.insert(0, '..')
    
    from src.discovery.aws_provider import AWSProvider
    from src.discovery.azure_provider import AzureProvider
    from src.discovery.kubernetes_provider import KubernetesProvider
    from src.discovery.resource_graph import ResourceGraphBuilder
    from src.detection.detection_engine import DetectionEngine
    from src.risk.attack_graph import AttackGraphGenerator
    from src.risk.prioritizer import RiskPrioritizer
    from src.ai.predictive_detector import PredictiveDetector
    from src.ai.root_cause_analyzer import RootCauseAnalyzer
    from src.ai.autonomous_agent import AutonomousRemediationAgent
    from src.ai.cross_cloud_normalizer import CrossCloudNormalizer
    from src.remediation.recommender import RemediationRecommender
    from src.remediation.iac_generator import IaCPatchGenerator
    
    print_header()
    console.print()
    
    # Phase 1: Discovery
    console.print("[bold cyan]Phase 1: Multi-Cloud Asset Discovery[/bold cyan]")
    console.print("=" * 50)
    
    all_resources = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Discovering AWS resources...", total=None)
        aws = AWSProvider()
        await aws.connect()
        aws_resources = await aws.discover_resources()
        all_resources.extend(aws_resources)
        
        progress.update(task, description="Discovering Azure resources...")
        azure = AzureProvider()
        await azure.connect()
        azure_resources = await azure.discover_resources()
        all_resources.extend(azure_resources)
        
        progress.update(task, description="Discovering Kubernetes resources...")
        k8s = KubernetesProvider()
        await k8s.connect()
        k8s_resources = await k8s.discover_resources()
        all_resources.extend(k8s_resources)
    
    # Resource summary
    table = Table(title="Discovered Resources", show_header=True)
    table.add_column("Provider")
    table.add_column("Count")
    table.add_column("Types")
    
    table.add_row("AWS", str(len(aws_resources)), "S3, EC2, RDS, IAM, Lambda, EKS")
    table.add_row("Azure", str(len(azure_resources)), "Storage, VMs, SQL, KeyVault, NSG")
    table.add_row("Kubernetes", str(len(k8s_resources)), "Deployments, Pods, Secrets, RBAC")
    table.add_row("[bold]Total[/bold]", f"[bold]{len(all_resources)}[/bold]", "")
    
    console.print(table)
    console.print()
    
    # Phase 2: Detection
    console.print("[bold cyan]Phase 2: Misconfiguration Detection[/bold cyan]")
    console.print("=" * 50)
    
    # Build resource graph
    graph = ResourceGraphBuilder()
    graph.add_resources(all_resources)
    
    # Run detection
    engine = DetectionEngine()
    scan_result = engine.scan_resources(all_resources)
    
    # Findings table
    table = Table(title="Security Findings", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count")
    table.add_column("Status")
    
    table.add_row("[red]CRITICAL[/red]", str(scan_result.critical_count), "🔴" if scan_result.critical_count else "✅")
    table.add_row("[orange1]HIGH[/orange1]", str(scan_result.high_count), "🟠" if scan_result.high_count else "✅")
    table.add_row("[yellow]MEDIUM[/yellow]", str(scan_result.medium_count), "🟡" if scan_result.medium_count else "✅")
    table.add_row("[green]LOW[/green]", str(scan_result.low_count), "🟢")
    
    console.print(table)
    
    # Show sample findings
    console.print("\n[bold]Sample Critical/High Findings:[/bold]")
    critical_high = [m for m in scan_result.misconfigurations 
                    if m.severity.value in ["critical", "high"]][:5]
    
    for i, finding in enumerate(critical_high, 1):
        severity_color = "red" if finding.severity.value == "critical" else "orange1"
        console.print(f"  {i}. [{severity_color}]{finding.severity.value.upper()}[/{severity_color}] {finding.title}")
        console.print(f"     Resource: {finding.resource_name} ({finding.provider})")
    
    console.print()
    
    # Phase 3: Attack Path Analysis
    console.print("[bold cyan]Phase 3: Attack-Graph-Driven Prioritization[/bold cyan]")
    console.print("=" * 50)
    
    attack_gen = AttackGraphGenerator(graph)
    attack_paths = attack_gen.generate_attack_paths(scan_result.misconfigurations)
    attack_scenarios = attack_gen.generate_attack_scenarios(scan_result.misconfigurations)
    
    console.print(f"\n[bold red]⚠ {len(attack_paths)} Attack Paths Identified[/bold red]\n")
    
    for i, path in enumerate(attack_paths[:3], 1):
        tree = Tree(f"[bold]{path.name}[/bold] (Risk: {path.total_risk_score:.1f})")
        for node in path.nodes:
            tree.add(f"{node.resource_name} → {node.access_gained}")
        console.print(tree)
        console.print()
    
    if attack_scenarios:
        console.print("[bold]Attack Scenarios:[/bold]")
        for scenario in attack_scenarios[:2]:
            console.print(f"  • {scenario.name}")
            console.print(f"    [dim]{scenario.description[:100]}...[/dim]")
        console.print()
    
    # Phase 4: Predictive Analysis
    console.print("[bold cyan]Phase 4: Predictive Misconfiguration Detection[/bold cyan]")
    console.print("=" * 50)
    
    predictor = PredictiveDetector()
    predictions = predictor.analyze_and_predict(all_resources)
    
    console.print(f"\n[bold yellow]🔮 {len(predictions)} Predicted Future Issues[/bold yellow]\n")
    
    table = Table(show_header=True)
    table.add_column("Prediction")
    table.add_column("Confidence")
    table.add_column("Time to Occur")
    table.add_column("Risk if Occurred")
    
    for pred in predictions[:4]:
        table.add_row(
            pred.title[:50] + "..." if len(pred.title) > 50 else pred.title,
            f"{pred.confidence*100:.0f}%",
            pred.time_to_occurrence,
            f"[red]{pred.risk_if_occurred:.0f}[/red]" if pred.risk_if_occurred >= 70 else f"{pred.risk_if_occurred:.0f}"
        )
    
    console.print(table)
    console.print()
    
    # Phase 5: Root Cause Analysis
    console.print("[bold cyan]Phase 5: AI-Assisted Root Cause Analysis[/bold cyan]")
    console.print("=" * 50)
    
    rca = RootCauseAnalyzer()
    root_cause_result = rca.analyze(scan_result.misconfigurations, all_resources)
    
    console.print(f"\n[bold]🔍 Root Causes Identified: {len(root_cause_result.root_causes)}[/bold]\n")
    
    for rc in root_cause_result.root_causes[:3]:
        console.print(f"  [{rc.category.value.upper()}] {rc.title}")
        console.print(f"  [dim]Confidence: {rc.confidence*100:.0f}% | Affected: {len(rc.affected_resources)} resources[/dim]")
        console.print()
    
    if root_cause_result.systemic_issues:
        console.print("[bold red]Systemic Issues:[/bold red]")
        for issue in root_cause_result.systemic_issues:
            console.print(f"  ⚠ {issue}")
        console.print()
    
    # Phase 6: Cross-Cloud Risk Normalization
    console.print("[bold cyan]Phase 6: Cross-Cloud Risk Normalization[/bold cyan]")
    console.print("=" * 50)
    
    normalizer = CrossCloudNormalizer()
    cross_cloud = normalizer.compare_across_clouds(scan_result.misconfigurations, all_resources)
    
    console.print("\n[bold]Risk by Provider:[/bold]")
    for provider, score in cross_cloud.risk_by_provider.items():
        bar_len = int(score / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        color = "red" if score >= 70 else ("yellow" if score >= 50 else "green")
        console.print(f"  {provider.upper():12} [{color}]{bar}[/{color}] {score:.1f}")
    
    console.print("\n[bold]Multi-Cloud Recommendations:[/bold]")
    for rec in cross_cloud.recommendations[:3]:
        console.print(f"  • {rec}")
    console.print()
    
    # Phase 7: Autonomous Remediation
    console.print("[bold cyan]Phase 7: Autonomous Remediation Agent[/bold cyan]")
    console.print("=" * 50)
    
    recommender = RemediationRecommender()
    remediations = recommender.recommend_batch(critical_high[:3])
    
    agent = AutonomousRemediationAgent()
    
    console.print("\n[bold]🤖 Remediation Analysis:[/bold]\n")
    
    table = Table(show_header=True)
    table.add_column("Issue")
    table.add_column("Decision")
    table.add_column("Reasoning")
    
    for rem in remediations[:3]:
        action = rem.remediation_action
        evaluation = agent.evaluate_remediation(
            next(m for m in scan_result.misconfigurations if m.id == rem.misconfiguration_id),
            action
        )
        
        decision_color = "green" if evaluation.decision.value == "auto_remediate" else "yellow"
        table.add_row(
            action.title[:40],
            f"[{decision_color}]{evaluation.decision.value}[/{decision_color}]",
            evaluation.reasoning[:50] + "..."
        )
    
    console.print(table)
    console.print()
    
    # Phase 8: IaC Patches
    console.print("[bold cyan]Phase 8: IaC Patch Generation[/bold cyan]")
    console.print("=" * 50)
    
    iac_gen = IaCPatchGenerator()
    
    console.print("\n[bold]Generated Terraform Patches:[/bold]\n")
    
    for finding in critical_high[:2]:
        patch_result = iac_gen.generate_patch(finding, "terraform")
        if patch_result.success and patch_result.patch:
            console.print(f"[bold]📝 {patch_result.patch.description}[/bold]")
            console.print(f"[dim]File: {patch_result.patch.file_path}[/dim]")
            console.print()
            console.print(Panel(patch_result.patch.patched_content, title="Secure Configuration", border_style="green"))
            console.print()
    
    # Summary
    console.print("[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]                    SCAN SUMMARY                    [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
    
    grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}
    grade = scan_result.overall_grade
    
    console.print(Panel.fit(
        f"[bold]Security Grade: [{grade_colors.get(grade, 'white')}]{grade}[/{grade_colors.get(grade, 'white')}][/bold]\n"
        f"Overall Risk Score: {scan_result.overall_risk_score:.1f}/100\n"
        f"\n"
        f"Resources Scanned: {len(all_resources)}\n"
        f"Misconfigurations Found: {len(scan_result.misconfigurations)}\n"
        f"Attack Paths Identified: {len(attack_paths)}\n"
        f"Predictions Generated: {len(predictions)}\n"
        f"Auto-Remediable Issues: {sum(1 for r in remediations if r.remediation_action.automated)}",
        title="[bold blue]CloudSentinel Assessment Complete[/bold blue]",
        border_style="blue"
    ))
    
    return scan_result


def main():
    """Entry point"""
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
