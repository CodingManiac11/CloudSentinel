"""
Risk Prioritizer

AI-driven prioritization of security findings.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import math

from ..models.misconfiguration import Misconfiguration, AttackPath, Severity


@dataclass
class PrioritizedFinding:
    """A finding with priority context"""
    misconfiguration: Misconfiguration
    priority_rank: int
    priority_score: float
    priority_reasons: List[str]
    recommended_action: str
    time_to_fix: str  # estimated


class RiskPrioritizer:
    """
    AI-driven prioritization that surfaces "what matters now".
    
    Instead of overwhelming users with hundreds of alerts, we:
    1. Correlate related issues
    2. Consider attack path position
    3. Factor in organizational context
    4. Surface the most impactful issues first
    """
    
    def __init__(self):
        # Severity weights for prioritization
        self.severity_weights = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 70,
            Severity.MEDIUM: 40,
            Severity.LOW: 20,
            Severity.INFO: 5,
        }
        
        # Category urgency multipliers
        self.category_urgency = {
            "public_exposure": 1.5,
            "iam_overprivilege": 1.3,
            "network_security": 1.2,
            "encryption": 1.1,
            "kubernetes_security": 1.2,
            "authentication": 1.4,
        }
    
    def prioritize_findings(
        self,
        misconfigurations: List[Misconfiguration],
        attack_paths: List[AttackPath] = None
    ) -> List[PrioritizedFinding]:
        """
        Prioritize findings considering multiple factors.
        """
        # Calculate priority scores
        scored_findings = []
        
        # Build attack path lookup for bonus scoring
        attack_path_resources = set()
        if attack_paths:
            for path in attack_paths:
                for node in path.nodes:
                    attack_path_resources.add(node.resource_id)
        
        for misc in misconfigurations:
            score, reasons = self._calculate_priority_score(
                misc, attack_path_resources
            )
            scored_findings.append({
                "misconfiguration": misc,
                "score": score,
                "reasons": reasons,
            })
        
        # Sort by score
        scored_findings.sort(key=lambda x: x["score"], reverse=True)
        
        # Create prioritized findings with ranks
        prioritized = []
        for rank, item in enumerate(scored_findings, 1):
            misc = item["misconfiguration"]
            prioritized.append(PrioritizedFinding(
                misconfiguration=misc,
                priority_rank=rank,
                priority_score=item["score"],
                priority_reasons=item["reasons"],
                recommended_action=self._get_recommended_action(misc),
                time_to_fix=self._estimate_fix_time(misc),
            ))
        
        return prioritized
    
    def get_top_priorities(
        self,
        misconfigurations: List[Misconfiguration],
        attack_paths: List[AttackPath] = None,
        top_n: int = 10
    ) -> List[PrioritizedFinding]:
        """Get the top N priority findings."""
        all_prioritized = self.prioritize_findings(misconfigurations, attack_paths)
        return all_prioritized[:top_n]
    
    def group_related_findings(
        self,
        findings: List[Misconfiguration]
    ) -> Dict[str, List[Misconfiguration]]:
        """
        Group related findings to reduce noise.
        Instead of showing 10 similar issues, show 1 with count.
        """
        groups = {}
        
        for finding in findings:
            # Group by resource
            resource_key = finding.resource_id
            if resource_key not in groups:
                groups[resource_key] = []
            groups[resource_key].append(finding)
        
        return groups
    
    def summarize_priorities(
        self,
        prioritized: List[PrioritizedFinding]
    ) -> Dict[str, Any]:
        """Generate executive summary of priorities."""
        if not prioritized:
            return {"message": "No findings to prioritize"}
        
        # Top 3 most important
        top_3 = prioritized[:3]
        
        # Statistics
        critical = sum(1 for p in prioritized if p.misconfiguration.severity == Severity.CRITICAL)
        high = sum(1 for p in prioritized if p.misconfiguration.severity == Severity.HIGH)
        
        # Unique resources affected
        unique_resources = len(set(p.misconfiguration.resource_id for p in prioritized))
        
        return {
            "total_findings": len(prioritized),
            "critical_count": critical,
            "high_count": high,
            "unique_resources_affected": unique_resources,
            "top_priorities": [
                {
                    "rank": p.priority_rank,
                    "title": p.misconfiguration.title,
                    "resource": p.misconfiguration.resource_name,
                    "severity": p.misconfiguration.severity.value,
                    "priority_score": round(p.priority_score, 1),
                    "reasons": p.priority_reasons[:2],
                    "recommended_action": p.recommended_action,
                    "time_to_fix": p.time_to_fix,
                }
                for p in top_3
            ],
            "recommended_focus": self._generate_focus_recommendation(prioritized[:5]),
        }
    
    def _calculate_priority_score(
        self,
        misc: Misconfiguration,
        attack_path_resources: set
    ) -> tuple:
        """Calculate priority score and reasons."""
        reasons = []
        score = 0.0
        
        # Base score from severity
        base_score = self.severity_weights.get(misc.severity, 20)
        score += base_score
        
        if misc.severity == Severity.CRITICAL:
            reasons.append("Critical severity issue")
        elif misc.severity == Severity.HIGH:
            reasons.append("High severity issue")
        
        # Add risk score if available
        if misc.risk_score:
            risk_bonus = misc.risk_score.score * 0.5
            score += risk_bonus
            
            if misc.risk_score.score >= 80:
                reasons.append(f"Very high risk score ({misc.risk_score.score:.0f})")
            elif misc.risk_score.score >= 60:
                reasons.append(f"Elevated risk score ({misc.risk_score.score:.0f})")
        
        # Category urgency multiplier
        category_mult = self.category_urgency.get(misc.category.value, 1.0)
        score *= category_mult
        
        if category_mult >= 1.3:
            reasons.append(f"Urgent category: {misc.category.value.replace('_', ' ')}")
        
        # Attack path bonus
        if misc.resource_id in attack_path_resources:
            score *= 1.4
            reasons.append("Part of identified attack path")
        
        # Related attack paths bonus
        if misc.attack_paths:
            score *= (1 + 0.1 * len(misc.attack_paths))
            reasons.append(f"Enables {len(misc.attack_paths)} attack scenarios")
        
        return score, reasons
    
    def _get_recommended_action(self, misc: Misconfiguration) -> str:
        """Get a recommended action for the finding."""
        category = misc.category.value
        
        actions = {
            "public_exposure": "Restrict public access and implement access controls",
            "iam_overprivilege": "Review and reduce permissions to least privilege",
            "network_security": "Update security group rules to restrict access",
            "encryption": "Enable encryption at rest and in transit",
            "kubernetes_security": "Apply pod security policies and restrict privileges",
            "authentication": "Enable MFA and strengthen authentication",
            "data_protection": "Enable backups and data protection controls",
        }
        
        return actions.get(category, "Review and remediate the misconfiguration")
    
    def _estimate_fix_time(self, misc: Misconfiguration) -> str:
        """Estimate time to fix based on complexity."""
        # Simple heuristics
        category = misc.category.value
        
        quick_fixes = ["encryption", "logging_monitoring"]
        medium_fixes = ["network_security", "authentication"]
        
        if category in quick_fixes:
            return "5-15 minutes"
        elif category in medium_fixes:
            return "15-30 minutes"
        else:
            return "30-60 minutes"
    
    def _generate_focus_recommendation(self, top_findings: List[PrioritizedFinding]) -> str:
        """Generate a recommendation for where to focus."""
        if not top_findings:
            return "No critical issues found - maintain current security posture."
        
        # Check for common themes
        categories = [f.misconfiguration.category.value for f in top_findings]
        most_common = max(set(categories), key=categories.count)
        
        if categories.count("public_exposure") >= 2:
            return "Focus on securing publicly exposed resources first - these pose immediate breach risk."
        elif categories.count("iam_overprivilege") >= 2:
            return "Prioritize IAM remediation - over-privileged access enables attack escalation."
        elif categories.count("encryption") >= 2:
            return "Enable encryption across all data stores to protect sensitive information."
        else:
            return f"Address the top {min(3, len(top_findings))} findings to significantly reduce risk."
