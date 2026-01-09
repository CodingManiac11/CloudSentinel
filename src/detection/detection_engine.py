"""
Detection Engine

Orchestrates the full detection pipeline from resources to enriched findings.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid

from ..models.cloud_resource import CloudResource
from ..models.misconfiguration import Misconfiguration, ScanResult, Severity
from .rules.base_rule import get_rule_registry
from .context_analyzer import ContextAnalyzer
from .drift_detector import DriftDetector


class DetectionEngine:
    """
    Main detection engine that orchestrates:
    1. Rule-based detection
    2. Context enrichment
    3. Risk scoring
    4. Drift detection
    
    This is the core of CloudSentinel's detection capability.
    """
    
    def __init__(self):
        self.rule_registry = get_rule_registry()
        self.context_analyzer = ContextAnalyzer()
        self.drift_detector = DriftDetector()
    
    def scan_resources(
        self, 
        resources: List[CloudResource],
        include_drift: bool = True
    ) -> ScanResult:
        """
        Perform a full security scan on a list of resources.
        
        Args:
            resources: List of cloud resources to scan
            include_drift: Whether to include drift detection
            
        Returns:
            Complete scan result with all findings
        """
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        started_at = datetime.now()
        
        all_misconfigurations = []
        
        # Build resource lookup for context analysis
        resource_map = {r.id: r for r in resources}
        
        # Scan each resource
        for resource in resources:
            # Get related resources for context
            related = [resource_map[rid] for rid in resource.connected_to if rid in resource_map]
            
            # Run detection rules
            findings = self._detect_misconfigurations(resource)
            
            # Enrich each finding with context
            for finding in findings:
                enriched = self.context_analyzer.enrich_misconfiguration(
                    finding, resource, related
                )
                all_misconfigurations.append(enriched)
        
        # Perform drift detection
        drift_report = None
        if include_drift:
            drift_report = self.drift_detector.simulate_drift_for_demo(resources)
        
        # Create scan result
        result = ScanResult(
            scan_id=scan_id,
            started_at=started_at,
            completed_at=datetime.now(),
            resource_count=len(resources),
            misconfigurations=all_misconfigurations,
        )
        
        # Calculate statistics
        result.calculate_statistics()
        
        return result
    
    def scan_single_resource(
        self, 
        resource: CloudResource,
        context_resources: List[CloudResource] = None
    ) -> List[Misconfiguration]:
        """
        Scan a single resource for misconfigurations.
        """
        findings = self._detect_misconfigurations(resource)
        
        # Enrich with context
        enriched_findings = []
        for finding in findings:
            enriched = self.context_analyzer.enrich_misconfiguration(
                finding, resource, context_resources or []
            )
            enriched_findings.append(enriched)
        
        return enriched_findings
    
    def _detect_misconfigurations(self, resource: CloudResource) -> List[Misconfiguration]:
        """
        Run all applicable rules against a resource.
        """
        return self.rule_registry.evaluate_resource(resource)
    
    def prioritize_findings(
        self, 
        findings: List[Misconfiguration]
    ) -> List[Misconfiguration]:
        """
        Prioritize findings using attack-graph-driven approach.
        
        This is where we implement "what matters now" rather than listing everything.
        """
        # Sort by risk score (highest first)
        sorted_findings = sorted(
            findings,
            key=lambda f: f.risk_score.score if f.risk_score else 0,
            reverse=True
        )
        
        # Group related findings (same resource or attack path)
        prioritized = []
        seen_resources = set()
        
        # First pass: Add highest priority unique resource findings
        for finding in sorted_findings:
            if finding.resource_id not in seen_resources:
                prioritized.append(finding)
                seen_resources.add(finding.resource_id)
        
        return prioritized
    
    def get_finding_summary(self, result: ScanResult) -> Dict[str, Any]:
        """
        Generate an executive summary of scan findings.
        """
        # Get top critical findings
        critical_findings = [
            f for f in result.misconfigurations 
            if f.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        
        # Group by category
        by_category = {}
        for finding in result.misconfigurations:
            cat = finding.category.value
            if cat not in by_category:
                by_category[cat] = 0
            by_category[cat] += 1
        
        # Calculate risk trends
        return {
            "scan_id": result.scan_id,
            "timestamp": result.completed_at.isoformat() if result.completed_at else None,
            "overall_grade": result.overall_grade,
            "overall_risk_score": result.overall_risk_score,
            "findings_summary": {
                "total": len(result.misconfigurations),
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
            },
            "by_category": by_category,
            "top_issues": [
                {
                    "title": f.title,
                    "resource": f.resource_name,
                    "severity": f.severity.value,
                    "risk_score": f.risk_score.score if f.risk_score else 0,
                }
                for f in self.prioritize_findings(critical_findings)[:5]
            ],
            "attack_paths": len(result.attack_paths),
        }
