"""
CloudSentinel Main Entry Point

Provides the main scanner orchestration.
"""

import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from .discovery.aws_provider import AWSProvider
from .discovery.azure_provider import AzureProvider
from .discovery.kubernetes_provider import KubernetesProvider
from .discovery.resource_graph import ResourceGraphBuilder
from .detection.detection_engine import DetectionEngine
from .risk.attack_graph import AttackGraphGenerator
from .risk.prioritizer import RiskPrioritizer
from .ai.predictive_detector import PredictiveDetector
from .ai.root_cause_analyzer import RootCauseAnalyzer
from .ai.autonomous_agent import AutonomousRemediationAgent
from .ai.cross_cloud_normalizer import CrossCloudNormalizer
from .remediation.recommender import RemediationRecommender
from .remediation.iac_generator import IaCPatchGenerator
from .remediation.workflow import RemediationWorkflow


class CloudSentinel:
    """
    Main orchestrator for CloudSentinel security scanning.
    
    This is the primary interface for running scans and managing security.
    """
    
    def __init__(self):
        self.providers = {}
        self.graph = ResourceGraphBuilder()
        self.detection_engine = DetectionEngine()
        self.prioritizer = RiskPrioritizer()
        self.predictor = PredictiveDetector()
        self.root_cause = RootCauseAnalyzer()
        self.normalizer = CrossCloudNormalizer()
        self.recommender = RemediationRecommender()
        self.iac_generator = IaCPatchGenerator()
        self.workflow = RemediationWorkflow()
        self.remediation_agent = AutonomousRemediationAgent()
    
    async def scan(
        self,
        providers: List[str] = None,
        demo_mode: bool = True
    ) -> Dict[str, Any]:
        """
        Run a complete security scan.
        
        Args:
            providers: List of providers to scan (aws, azure, kubernetes)
            demo_mode: Use simulated infrastructure
            
        Returns:
            Complete scan results
        """
        providers = providers or ["aws", "azure", "kubernetes"]
        all_resources = []
        
        # Discovery phase
        if "aws" in providers:
            aws = AWSProvider()
            await aws.connect()
            resources = await aws.discover_resources()
            all_resources.extend(resources)
        
        if "azure" in providers:
            azure = AzureProvider()
            await azure.connect()
            resources = await azure.discover_resources()
            all_resources.extend(resources)
        
        if "kubernetes" in providers:
            k8s = KubernetesProvider()
            await k8s.connect()
            resources = await k8s.discover_resources()
            all_resources.extend(resources)
        
        # Build resource graph
        self.graph = ResourceGraphBuilder()
        self.graph.add_resources(all_resources)
        
        # Detection phase
        scan_result = self.detection_engine.scan_resources(all_resources)
        
        # Attack path analysis
        attack_gen = AttackGraphGenerator(self.graph)
        attack_paths = attack_gen.generate_attack_paths(scan_result.misconfigurations)
        attack_scenarios = attack_gen.generate_attack_scenarios(scan_result.misconfigurations)
        scan_result.attack_paths = attack_paths
        
        # Prioritization
        prioritized = self.prioritizer.prioritize_findings(
            scan_result.misconfigurations, attack_paths
        )
        priority_summary = self.prioritizer.summarize_priorities(prioritized)
        
        # Predictive analysis
        predictions = self.predictor.analyze_and_predict(all_resources)
        prediction_summary = self.predictor.get_prediction_summary(predictions)
        
        # Root cause analysis
        rca = self.root_cause.analyze(scan_result.misconfigurations, all_resources)
        
        # Cross-cloud normalization
        cross_cloud = self.normalizer.compare_across_clouds(
            scan_result.misconfigurations, all_resources
        )
        
        # Generate remediations
        remediations = self.recommender.recommend_batch(
            [m for m in scan_result.misconfigurations if m.severity.value in ["critical", "high"]]
        )
        
        return {
            "scan_id": scan_result.scan_id,
            "timestamp": datetime.now().isoformat(),
            "resources_scanned": len(all_resources),
            "scan_result": scan_result.to_dict(),
            "attack_paths": [ap.to_dict() for ap in attack_paths],
            "attack_scenarios": [
                {
                    "id": s.id,
                    "name": s.name,
                    "description": s.description,
                    "risk_score": s.total_risk_score,
                    "path_count": len(s.paths),
                }
                for s in attack_scenarios
            ],
            "priority_summary": priority_summary,
            "predictions": prediction_summary,
            "root_cause_analysis": rca.summary,
            "cross_cloud_comparison": {
                "providers": cross_cloud.providers,
                "risk_by_provider": cross_cloud.risk_by_provider,
                "recommendations": cross_cloud.recommendations,
            },
            "remediation_count": len(remediations),
            "overall_grade": scan_result.overall_grade,
            "overall_risk_score": scan_result.overall_risk_score,
        }
    
    def run_scan_sync(
        self,
        providers: List[str] = None,
        demo_mode: bool = True
    ) -> Dict[str, Any]:
        """Synchronous wrapper for scan"""
        return asyncio.run(self.scan(providers, demo_mode))


def main():
    """Main entry point"""
    from .cli.scanner_cli import cli
    cli()


if __name__ == "__main__":
    main()
