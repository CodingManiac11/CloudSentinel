"""
Cross-Cloud Risk Normalizer

Normalizes risk across different cloud providers for unified analysis.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from ..models.cloud_resource import CloudResource, CloudProvider, ResourceType
from ..models.misconfiguration import Misconfiguration, Severity


class NormalizedRiskLevel(str, Enum):
    """Unified risk levels across cloud providers"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class NormalizedFinding:
    """A finding normalized across cloud providers"""
    original_finding: Misconfiguration
    normalized_severity: NormalizedRiskLevel
    normalized_category: str
    normalized_controls: List[str]
    
    # Cross-cloud context
    equivalent_in_other_clouds: List[str]
    unified_risk_score: float
    
    # Comparison
    provider_specific_notes: str


@dataclass
class CrossCloudComparison:
    """Comparison of risk posture across cloud providers"""
    providers: List[str]
    risk_by_provider: Dict[str, float]
    findings_by_provider: Dict[str, int]
    common_issues: List[str]
    provider_specific_issues: Dict[str, List[str]]
    recommendations: List[str]


class CrossCloudNormalizer:
    """
    Normalizes security findings across AWS, Azure, GCP, and Kubernetes
    for unified risk management.
    
    This enables:
    - Consistent risk scoring regardless of cloud
    - Comparison of security posture across providers
    - Unified compliance reporting
    - Multi-cloud attack path analysis
    """
    
    def __init__(self):
        # Resource type mappings across clouds
        self.resource_mappings = {
            # Storage
            "s3": ("object_storage", ["Azure Blob", "GCS Bucket", "S3 Bucket"]),
            "azure_blob": ("object_storage", ["S3 Bucket", "GCS Bucket", "Azure Blob"]),
            "gcs": ("object_storage", ["S3 Bucket", "Azure Blob", "GCS Bucket"]),
            
            # Compute
            "ec2": ("compute", ["Azure VM", "GCE Instance", "EC2"]),
            "azure_vm": ("compute", ["EC2", "GCE Instance", "Azure VM"]),
            
            # Database
            "rds": ("database", ["Azure SQL", "Cloud SQL", "RDS"]),
            "azure_sql": ("database", ["RDS", "Cloud SQL", "Azure SQL"]),
            
            # IAM
            "iam_role": ("identity", ["Azure AD", "GCP IAM", "IAM Role"]),
            "azure_ad": ("identity", ["IAM Role", "GCP IAM", "Azure AD"]),
        }
        
        # Severity normalization
        self.severity_weights = {
            # AWS tends to have more granular severities
            Severity.CRITICAL: NormalizedRiskLevel.CRITICAL,
            Severity.HIGH: NormalizedRiskLevel.HIGH,
            Severity.MEDIUM: NormalizedRiskLevel.MEDIUM,
            Severity.LOW: NormalizedRiskLevel.LOW,
            Severity.INFO: NormalizedRiskLevel.MINIMAL,
        }
        
        # Compliance control mappings
        self.control_mappings = {
            "CIS-AWS-2.1.1": "CIS-Benchmark-Storage-Encryption",
            "CIS-Azure-3.7": "CIS-Benchmark-Storage-Encryption",
            "CIS-AWS-1.16": "CIS-Benchmark-IAM-Least-Privilege",
            "CIS-Azure-1.23": "CIS-Benchmark-IAM-Least-Privilege",
            "CIS-AWS-5.2": "CIS-Benchmark-Network-Security",
            "CIS-Azure-6.1": "CIS-Benchmark-Network-Security",
        }
    
    def normalize_finding(self, finding: Misconfiguration) -> NormalizedFinding:
        """
        Normalize a finding for cross-cloud comparison.
        """
        # Normalize severity
        normalized_severity = self.severity_weights.get(
            finding.severity, NormalizedRiskLevel.MEDIUM
        )
        
        # Normalize category
        normalized_category = self._normalize_category(finding.category.value)
        
        # Map compliance controls
        normalized_controls = []
        for control in finding.compliance_violations:
            if control in self.control_mappings:
                normalized_controls.append(self.control_mappings[control])
            else:
                normalized_controls.append(control)
        normalized_controls = list(set(normalized_controls))
        
        # Find equivalents in other clouds
        equivalents = self._find_equivalents(finding)
        
        # Calculate unified risk score
        unified_score = self._calculate_unified_score(finding, normalized_severity)
        
        # Provider-specific notes
        notes = self._get_provider_notes(finding)
        
        return NormalizedFinding(
            original_finding=finding,
            normalized_severity=normalized_severity,
            normalized_category=normalized_category,
            normalized_controls=normalized_controls,
            equivalent_in_other_clouds=equivalents,
            unified_risk_score=unified_score,
            provider_specific_notes=notes,
        )
    
    def compare_across_clouds(
        self,
        findings: List[Misconfiguration],
        resources: List[CloudResource]
    ) -> CrossCloudComparison:
        """
        Compare security posture across different cloud providers.
        """
        # Group by provider
        findings_by_provider: Dict[str, List[Misconfiguration]] = {}
        resources_by_provider: Dict[str, List[CloudResource]] = {}
        
        for finding in findings:
            provider = finding.provider
            if provider not in findings_by_provider:
                findings_by_provider[provider] = []
            findings_by_provider[provider].append(finding)
        
        for resource in resources:
            provider = resource.provider.value
            if provider not in resources_by_provider:
                resources_by_provider[provider] = []
            resources_by_provider[provider].append(resource)
        
        # Calculate risk score per provider
        risk_by_provider = {}
        for provider, provider_findings in findings_by_provider.items():
            if provider_findings:
                scores = [
                    f.risk_score.score if f.risk_score else 50
                    for f in provider_findings
                ]
                risk_by_provider[provider] = sum(scores) / len(scores)
            else:
                risk_by_provider[provider] = 0
        
        # Find common issues
        common_issues = self._find_common_issues(findings_by_provider)
        
        # Find provider-specific issues
        provider_specific = self._find_provider_specific_issues(findings_by_provider)
        
        # Generate recommendations
        recommendations = self._generate_cross_cloud_recommendations(
            risk_by_provider, common_issues
        )
        
        return CrossCloudComparison(
            providers=list(findings_by_provider.keys()),
            risk_by_provider=risk_by_provider,
            findings_by_provider={p: len(f) for p, f in findings_by_provider.items()},
            common_issues=common_issues,
            provider_specific_issues=provider_specific,
            recommendations=recommendations,
        )
    
    def _normalize_category(self, category: str) -> str:
        """Normalize category to unified taxonomy"""
        category_map = {
            "public_exposure": "Access Control",
            "iam_overprivilege": "Identity & Access",
            "network_security": "Network Security",
            "encryption": "Data Protection",
            "kubernetes_security": "Container Security",
            "authentication": "Authentication",
            "data_protection": "Data Protection",
        }
        return category_map.get(category, category)
    
    def _find_equivalents(self, finding: Misconfiguration) -> List[str]:
        """Find equivalent issues in other cloud providers"""
        equivalents = []
        category = finding.category.value
        
        equivalent_map = {
            "public_exposure": [
                "AWS: Public S3 Bucket",
                "Azure: Public Blob Storage",
                "GCP: Public GCS Bucket",
            ],
            "iam_overprivilege": [
                "AWS: Over-privileged IAM Role",
                "Azure: Excessive Azure AD permissions",
                "GCP: Over-privileged Service Account",
            ],
            "network_security": [
                "AWS: Permissive Security Group",
                "Azure: Open NSG rules",
                "GCP: Open Firewall rules",
            ],
        }
        
        if category in equivalent_map:
            # Return equivalents for OTHER providers
            for equiv in equivalent_map[category]:
                if finding.provider.lower() not in equiv.lower():
                    equivalents.append(equiv)
        
        return equivalents
    
    def _calculate_unified_score(
        self,
        finding: Misconfiguration,
        normalized_severity: NormalizedRiskLevel
    ) -> float:
        """Calculate a unified risk score for cross-cloud comparison"""
        severity_scores = {
            NormalizedRiskLevel.CRITICAL: 90,
            NormalizedRiskLevel.HIGH: 70,
            NormalizedRiskLevel.MEDIUM: 50,
            NormalizedRiskLevel.LOW: 30,
            NormalizedRiskLevel.MINIMAL: 10,
        }
        
        base_score = severity_scores.get(normalized_severity, 50)
        
        # Adjust based on original risk score if available
        if finding.risk_score:
            base_score = (base_score + finding.risk_score.score) / 2
        
        return round(base_score, 1)
    
    def _get_provider_notes(self, finding: Misconfiguration) -> str:
        """Get provider-specific notes for a finding"""
        provider = finding.provider.lower()
        category = finding.category.value
        
        notes = {
            ("aws", "public_exposure"): "AWS S3 buckets require explicit public access blocks",
            ("aws", "iam_overprivilege"): "Use AWS IAM Access Analyzer to audit permissions",
            ("azure", "public_exposure"): "Azure Storage accounts have account-level public access settings",
            ("azure", "network_security"): "Azure NSGs operate at subnet and NIC levels",
            ("kubernetes", "kubernetes_security"): "Consider enabling Pod Security Standards (PSS)",
        }
        
        return notes.get((provider, category), f"Standard {provider.upper()} remediation applies")
    
    def _find_common_issues(
        self,
        findings_by_provider: Dict[str, List[Misconfiguration]]
    ) -> List[str]:
        """Find issues that are common across multiple providers"""
        category_by_provider = {}
        
        for provider, findings in findings_by_provider.items():
            category_by_provider[provider] = set(f.category.value for f in findings)
        
        # Find intersection of categories
        if len(category_by_provider) < 2:
            return []
        
        all_categories = list(category_by_provider.values())
        common = all_categories[0]
        for cats in all_categories[1:]:
            common = common.intersection(cats)
        
        return [f"Multi-cloud issue: {self._normalize_category(c)}" for c in common]
    
    def _find_provider_specific_issues(
        self,
        findings_by_provider: Dict[str, List[Misconfiguration]]
    ) -> Dict[str, List[str]]:
        """Find issues unique to each provider"""
        specific = {}
        
        for provider, findings in findings_by_provider.items():
            categories = set(f.category.value for f in findings)
            # For demo, just list top categories
            specific[provider] = [
                f.title for f in sorted(
                    findings, 
                    key=lambda x: x.risk_score.score if x.risk_score else 0,
                    reverse=True
                )[:3]
            ]
        
        return specific
    
    def _generate_cross_cloud_recommendations(
        self,
        risk_by_provider: Dict[str, float],
        common_issues: List[str]
    ) -> List[str]:
        """Generate recommendations for multi-cloud security"""
        recommendations = []
        
        if common_issues:
            recommendations.append(
                "Address common issues across all providers to improve overall security posture"
            )
        
        # Find highest risk provider
        if risk_by_provider:
            highest_risk = max(risk_by_provider.items(), key=lambda x: x[1])
            if highest_risk[1] >= 70:
                recommendations.append(
                    f"Prioritize remediation in {highest_risk[0].upper()} which has highest risk score"
                )
        
        recommendations.extend([
            "Implement consistent security policies across all cloud providers",
            "Use unified CSPM tooling for cross-cloud visibility",
            "Establish common tagging standards for multi-cloud resources",
        ])
        
        return recommendations
