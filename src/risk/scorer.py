"""
Risk Scorer

Dynamic risk scoring based on multiple factors.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from ..models.cloud_resource import CloudResource, DataSensitivity, ExposureLevel
from ..models.misconfiguration import Misconfiguration, RiskFactors, RiskScore, Severity


@dataclass
class RiskTrend:
    """Tracks risk score changes over time"""
    resource_id: str
    timestamps: List[datetime]
    scores: List[float]
    
    def get_trend(self) -> str:
        """Determine if risk is increasing, decreasing, or stable"""
        if len(self.scores) < 2:
            return "stable"
        
        recent_avg = sum(self.scores[-3:]) / min(3, len(self.scores))
        older_avg = sum(self.scores[:3]) / min(3, len(self.scores))
        
        diff = recent_avg - older_avg
        if diff > 5:
            return "increasing"
        elif diff < -5:
            return "decreasing"
        return "stable"


class RiskScorer:
    """
    Calculates dynamic risk scores using multiple weighted factors.
    
    Unlike static CVSS-style scoring, this considers:
    - Real-time context (what data is there, who can access it)
    - Blast radius (what else gets compromised)
    - Attack path position (is this a stepping stone?)
    - Compensating controls (what mitigations exist)
    """
    
    def __init__(self):
        self.risk_history: Dict[str, RiskTrend] = {}
        
        # Weights for different risk factors
        self.weights = {
            "asset_criticality": 0.15,
            "data_sensitivity": 0.20,
            "exposure_surface": 0.18,
            "blast_radius": 0.17,
            "exploit_feasibility": 0.20,
            "attack_path_position": 0.10,
        }
    
    def calculate_resource_risk(
        self,
        resource: CloudResource,
        misconfigurations: List[Misconfiguration] = None,
        connected_resources: List[CloudResource] = None
    ) -> RiskScore:
        """
        Calculate overall risk score for a resource.
        """
        factors = RiskFactors()
        
        # Asset criticality (from resource itself)
        factors.asset_criticality = resource.criticality_score
        
        # Data sensitivity
        sensitivity_map = {
            DataSensitivity.RESTRICTED: 1.0,
            DataSensitivity.CONFIDENTIAL: 0.75,
            DataSensitivity.INTERNAL: 0.5,
            DataSensitivity.PUBLIC: 0.2,
            DataSensitivity.UNKNOWN: 0.5,
        }
        factors.data_sensitivity = sensitivity_map.get(resource.data_sensitivity, 0.5)
        
        # Exposure surface
        exposure_map = {
            ExposureLevel.INTERNET: 1.0,
            ExposureLevel.VPC_INTERNAL: 0.5,
            ExposureLevel.PRIVATE: 0.3,
            ExposureLevel.ISOLATED: 0.1,
        }
        factors.exposure_surface = exposure_map.get(resource.exposure_level, 0.5)
        
        if resource.config.public_access:
            factors.exposure_surface = max(factors.exposure_surface, 0.9)
        
        # Blast radius
        factors.blast_radius = self._calculate_blast_radius_score(
            resource, connected_resources or []
        )
        
        # Exploit feasibility (based on misconfigurations)
        if misconfigurations:
            severity_scores = {
                Severity.CRITICAL: 1.0,
                Severity.HIGH: 0.8,
                Severity.MEDIUM: 0.5,
                Severity.LOW: 0.3,
            }
            max_severity = max(
                [severity_scores.get(m.severity, 0.5) for m in misconfigurations],
                default=0.3
            )
            factors.exploit_feasibility = max_severity
        else:
            factors.exploit_feasibility = 0.3
        
        # Attack path position (would be calculated by attack graph)
        factors.attack_path_position = 0.0  # Default, updated by attack graph analysis
        
        # Compensating controls
        factors.compensating_controls = self._calculate_compensating_controls(resource)
        
        # Generate justification
        justification = self._generate_justification(resource, factors)
        
        return RiskScore.from_factors(factors, justification)
    
    def calculate_aggregate_risk(
        self,
        resources: List[CloudResource],
        misconfigurations: List[Misconfiguration]
    ) -> Dict[str, Any]:
        """
        Calculate aggregate risk metrics across all resources.
        """
        resource_scores = []
        
        # Group misconfigurations by resource
        misconfig_by_resource: Dict[str, List[Misconfiguration]] = {}
        for m in misconfigurations:
            if m.resource_id not in misconfig_by_resource:
                misconfig_by_resource[m.resource_id] = []
            misconfig_by_resource[m.resource_id].append(m)
        
        resource_map = {r.id: r for r in resources}
        
        for resource in resources:
            resource_misconfigs = misconfig_by_resource.get(resource.id, [])
            connected = [resource_map[cid] for cid in resource.connected_to if cid in resource_map]
            
            score = self.calculate_resource_risk(resource, resource_misconfigs, connected)
            resource_scores.append({
                "resource_id": resource.id,
                "resource_name": resource.name,
                "score": score.score,
                "grade": score.grade,
                "misconfigurations": len(resource_misconfigs),
            })
        
        # Calculate overall metrics
        all_scores = [r["score"] for r in resource_scores]
        
        return {
            "total_resources": len(resources),
            "total_misconfigurations": len(misconfigurations),
            "average_risk_score": sum(all_scores) / len(all_scores) if all_scores else 0,
            "max_risk_score": max(all_scores) if all_scores else 0,
            "high_risk_resources": sum(1 for s in all_scores if s >= 70),
            "medium_risk_resources": sum(1 for s in all_scores if 40 <= s < 70),
            "low_risk_resources": sum(1 for s in all_scores if s < 40),
            "resource_scores": sorted(resource_scores, key=lambda x: x["score"], reverse=True),
        }
    
    def _calculate_blast_radius_score(
        self,
        resource: CloudResource,
        connected: List[CloudResource]
    ) -> float:
        """Calculate blast radius score based on connected resources"""
        if not connected:
            return 0.2
        
        # Count high-value connections
        high_value = sum(1 for r in connected if r.criticality_score >= 0.8)
        medium_value = sum(1 for r in connected if 0.5 <= r.criticality_score < 0.8)
        
        # Score based on connection value
        score = 0.2
        score += min(0.4, high_value * 0.15)
        score += min(0.2, medium_value * 0.05)
        score += min(0.2, len(connected) * 0.02)
        
        return min(1.0, score)
    
    def _calculate_compensating_controls(self, resource: CloudResource) -> float:
        """Calculate score for compensating controls (reduces risk)"""
        score = 0.0
        
        if resource.config.encryption_enabled:
            score += 0.25
        if resource.config.logging_enabled:
            score += 0.20
        if resource.config.mfa_enabled:
            score += 0.25
        if resource.config.versioning_enabled:
            score += 0.15
        
        # Check for additional controls in raw config
        config = resource.config.raw_config
        if config.get("deletion_protection"):
            score += 0.15
        
        return min(1.0, score)
    
    def _generate_justification(self, resource: CloudResource, factors: RiskFactors) -> str:
        """Generate human-readable risk justification"""
        high_factors = []
        
        if factors.data_sensitivity >= 0.75:
            high_factors.append("contains sensitive data")
        if factors.exposure_surface >= 0.8:
            high_factors.append("publicly exposed")
        if factors.blast_radius >= 0.6:
            high_factors.append("affects multiple critical resources")
        if factors.exploit_feasibility >= 0.7:
            high_factors.append("has easily exploitable misconfigurations")
        
        if high_factors:
            return f"Risk elevated because resource is {', '.join(high_factors)}."
        elif factors.compensating_controls >= 0.5:
            return "Risk reduced due to compensating security controls."
        else:
            return "Standard risk level based on resource configuration."
