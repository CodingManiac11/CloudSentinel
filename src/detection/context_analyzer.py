"""
Context Analyzer

Enriches misconfigurations with contextual information for accurate risk assessment.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from ..models.cloud_resource import CloudResource, ResourceType, DataSensitivity, ExposureLevel
from ..models.misconfiguration import Misconfiguration, RiskFactors, RiskScore


class ContextType(str, Enum):
    """Types of context to analyze"""
    DATA_SENSITIVITY = "data_sensitivity"
    NETWORK_EXPOSURE = "network_exposure"
    IAM_RELATIONSHIPS = "iam_relationships"
    BLAST_RADIUS = "blast_radius"
    COMPENSATING_CONTROLS = "compensating_controls"


@dataclass
class ContextResult:
    """Result of context analysis"""
    context_type: ContextType
    score: float  # 0-1 impact on risk
    findings: List[str]
    metadata: Dict[str, Any]


class ContextAnalyzer:
    """
    Analyzes context around misconfigurations to provide accurate risk assessment.
    
    This is what makes CloudSentinel different from static rule checkers - 
    we understand the CONTEXT of misconfigurations, not just their existence.
    """
    
    def __init__(self):
        self.sensitivity_keywords = {
            DataSensitivity.RESTRICTED: [
                "pii", "personal", "ssn", "credit", "password", "secret",
                "key", "token", "customer", "medical", "health", "financial"
            ],
            DataSensitivity.CONFIDENTIAL: [
                "internal", "private", "employee", "business", "proprietary"
            ],
            DataSensitivity.INTERNAL: [
                "dev", "test", "staging", "log", "metric", "debug"
            ],
        }
    
    def analyze_resource(self, resource: CloudResource, related_resources: List[CloudResource] = None) -> Dict[ContextType, ContextResult]:
        """
        Perform full context analysis on a resource.
        
        Returns a dictionary of context types to their analysis results.
        """
        results = {}
        
        results[ContextType.DATA_SENSITIVITY] = self._analyze_data_sensitivity(resource)
        results[ContextType.NETWORK_EXPOSURE] = self._analyze_network_exposure(resource)
        results[ContextType.BLAST_RADIUS] = self._analyze_blast_radius(resource, related_resources or [])
        results[ContextType.COMPENSATING_CONTROLS] = self._analyze_compensating_controls(resource)
        
        return results
    
    def calculate_risk_factors(
        self, 
        resource: CloudResource, 
        misconfiguration: Misconfiguration,
        context_results: Dict[ContextType, ContextResult]
    ) -> RiskFactors:
        """
        Calculate risk factors based on context analysis.
        """
        factors = RiskFactors()
        
        # Asset criticality from resource
        factors.asset_criticality = resource.criticality_score
        
        # Data sensitivity from context
        sensitivity_result = context_results.get(ContextType.DATA_SENSITIVITY)
        if sensitivity_result:
            factors.data_sensitivity = sensitivity_result.score
        
        # Exposure surface from context
        exposure_result = context_results.get(ContextType.NETWORK_EXPOSURE)
        if exposure_result:
            factors.exposure_surface = exposure_result.score
        
        # Blast radius from context
        blast_result = context_results.get(ContextType.BLAST_RADIUS)
        if blast_result:
            factors.blast_radius = blast_result.score
        
        # Exploit feasibility based on misconfiguration type
        factors.exploit_feasibility = self._calculate_exploit_feasibility(misconfiguration)
        
        # Compensating controls
        controls_result = context_results.get(ContextType.COMPENSATING_CONTROLS)
        if controls_result:
            factors.compensating_controls = controls_result.score
        
        return factors
    
    def enrich_misconfiguration(
        self, 
        misconfiguration: Misconfiguration, 
        resource: CloudResource,
        related_resources: List[CloudResource] = None
    ) -> Misconfiguration:
        """
        Enrich a misconfiguration with context-aware risk scoring.
        """
        # Analyze context
        context_results = self.analyze_resource(resource, related_resources)
        
        # Calculate risk factors
        risk_factors = self.calculate_risk_factors(resource, misconfiguration, context_results)
        
        # Generate justification
        justification = self._generate_risk_justification(
            resource, misconfiguration, risk_factors, context_results
        )
        
        # Create risk score
        misconfiguration.risk_score = RiskScore.from_factors(risk_factors, justification)
        
        # Add context to misconfiguration
        misconfiguration.context = {
            "data_sensitivity": context_results[ContextType.DATA_SENSITIVITY].metadata,
            "exposure": context_results[ContextType.NETWORK_EXPOSURE].metadata,
            "blast_radius": context_results[ContextType.BLAST_RADIUS].metadata,
        }
        
        return misconfiguration
    
    def _analyze_data_sensitivity(self, resource: CloudResource) -> ContextResult:
        """Analyze data sensitivity of a resource"""
        findings = []
        score = 0.5  # Default medium sensitivity
        
        # Use explicit sensitivity if set
        if resource.data_sensitivity == DataSensitivity.RESTRICTED:
            score = 1.0
            findings.append("Resource handles restricted/PII data")
        elif resource.data_sensitivity == DataSensitivity.CONFIDENTIAL:
            score = 0.75
            findings.append("Resource handles confidential data")
        elif resource.data_sensitivity == DataSensitivity.PUBLIC:
            score = 0.2
            findings.append("Resource handles public data")
        
        # Check tags for sensitivity hints
        tags = resource.metadata.tags
        for tag_key, tag_value in tags.items():
            tag_text = f"{tag_key} {tag_value}".lower()
            
            for sensitivity, keywords in self.sensitivity_keywords.items():
                if any(kw in tag_text for kw in keywords):
                    if sensitivity == DataSensitivity.RESTRICTED:
                        score = max(score, 0.95)
                        findings.append(f"Tag indicates sensitive data: {tag_key}={tag_value}")
                    elif sensitivity == DataSensitivity.CONFIDENTIAL:
                        score = max(score, 0.7)
        
        # Check resource type for inherent sensitivity
        high_value_types = [
            ResourceType.DATABASE, ResourceType.KEY_VAULT, 
            ResourceType.KUBERNETES_SECRET, ResourceType.IAM_ROLE
        ]
        if resource.resource_type in high_value_types:
            score = max(score, 0.7)
            findings.append(f"Resource type '{resource.resource_type.value}' typically contains sensitive data")
        
        return ContextResult(
            context_type=ContextType.DATA_SENSITIVITY,
            score=score,
            findings=findings,
            metadata={
                "sensitivity_level": resource.data_sensitivity.value,
                "inferred_score": score,
            }
        )
    
    def _analyze_network_exposure(self, resource: CloudResource) -> ContextResult:
        """Analyze network exposure of a resource"""
        findings = []
        score = 0.3  # Default low exposure
        
        # Check exposure level
        if resource.exposure_level == ExposureLevel.INTERNET:
            score = 1.0
            findings.append("Resource is directly exposed to the internet")
        elif resource.exposure_level == ExposureLevel.VPC_INTERNAL:
            score = 0.4
            findings.append("Resource is exposed within VPC")
        elif resource.exposure_level == ExposureLevel.PRIVATE:
            score = 0.2
        
        # Check for public access configuration
        if resource.config.public_access:
            score = max(score, 0.9)
            findings.append("Public access is enabled")
        
        # Check for exposed sensitive ports
        sensitive_ports = {22, 3389, 3306, 5432, 27017, 6379}
        exposed_sensitive = set(resource.config.ports_open) & sensitive_ports
        if exposed_sensitive:
            score = max(score, 0.8)
            findings.append(f"Sensitive ports exposed: {list(exposed_sensitive)}")
        
        return ContextResult(
            context_type=ContextType.NETWORK_EXPOSURE,
            score=score,
            findings=findings,
            metadata={
                "exposure_level": resource.exposure_level.value,
                "public_access": resource.config.public_access,
                "open_ports": resource.config.ports_open,
            }
        )
    
    def _analyze_blast_radius(self, resource: CloudResource, related_resources: List[CloudResource]) -> ContextResult:
        """Analyze potential blast radius if resource is compromised"""
        findings = []
        
        # Count directly connected resources
        connected_count = len(resource.connected_to)
        
        # Count high-value connected resources
        high_value_connected = 0
        for related in related_resources:
            if related.id in resource.connected_to:
                if related.criticality_score >= 0.7:
                    high_value_connected += 1
        
        # Calculate score based on connections
        if connected_count >= 10:
            score = 0.9
            findings.append(f"High connectivity: {connected_count} connected resources")
        elif connected_count >= 5:
            score = 0.7
            findings.append(f"Moderate connectivity: {connected_count} connected resources")
        elif connected_count >= 2:
            score = 0.5
        else:
            score = 0.3
        
        if high_value_connected > 0:
            score = min(1.0, score + 0.2)
            findings.append(f"{high_value_connected} high-value resources in blast radius")
        
        # IAM roles have inherently higher blast radius
        if resource.resource_type in [ResourceType.IAM_ROLE, ResourceType.SERVICE_ACCOUNT]:
            score = max(score, 0.8)
            findings.append("IAM resource can affect many other resources")
        
        return ContextResult(
            context_type=ContextType.BLAST_RADIUS,
            score=score,
            findings=findings,
            metadata={
                "connected_resources": connected_count,
                "high_value_connected": high_value_connected,
            }
        )
    
    def _analyze_compensating_controls(self, resource: CloudResource) -> ContextResult:
        """Analyze compensating controls that might reduce risk"""
        findings = []
        score = 0.0  # Start with no compensating controls
        
        config = resource.config
        
        # Check for encryption
        if config.encryption_enabled:
            score += 0.2
            findings.append("Encryption is enabled")
        
        # Check for logging
        if config.logging_enabled:
            score += 0.15
            findings.append("Logging is enabled")
        
        # Check for versioning (data protection)
        if config.versioning_enabled:
            score += 0.1
            findings.append("Versioning is enabled")
        
        # Check for MFA
        if config.mfa_enabled:
            score += 0.2
            findings.append("MFA is enabled")
        
        # Cap at 1.0
        score = min(score, 1.0)
        
        return ContextResult(
            context_type=ContextType.COMPENSATING_CONTROLS,
            score=score,
            findings=findings,
            metadata={
                "encryption": config.encryption_enabled,
                "logging": config.logging_enabled,
                "versioning": config.versioning_enabled,
                "mfa": config.mfa_enabled,
            }
        )
    
    def _calculate_exploit_feasibility(self, misconfiguration: Misconfiguration) -> float:
        """Calculate how easy it is to exploit this misconfiguration"""
        from ..models.misconfiguration import MisconfigCategory, Severity
        
        # Base score on severity
        severity_scores = {
            Severity.CRITICAL: 0.9,
            Severity.HIGH: 0.7,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }
        score = severity_scores.get(misconfiguration.severity, 0.5)
        
        # Adjust based on category
        easy_exploit_categories = [
            MisconfigCategory.PUBLIC_EXPOSURE,
            MisconfigCategory.AUTHENTICATION,
        ]
        if misconfiguration.category in easy_exploit_categories:
            score = min(1.0, score + 0.15)
        
        return score
    
    def _generate_risk_justification(
        self,
        resource: CloudResource,
        misconfiguration: Misconfiguration,
        factors: RiskFactors,
        context_results: Dict[ContextType, ContextResult]
    ) -> str:
        """Generate human-readable risk justification"""
        parts = []
        
        # Highlight highest risk factors
        if factors.exposure_surface >= 0.8:
            parts.append("highly exposed to the internet")
        
        if factors.data_sensitivity >= 0.8:
            parts.append("contains sensitive/restricted data")
        
        if factors.blast_radius >= 0.7:
            parts.append("compromise would affect multiple resources")
        
        if factors.exploit_feasibility >= 0.7:
            parts.append("easy to exploit")
        
        if parts:
            return f"This misconfiguration is high-risk because the resource is {', '.join(parts)}."
        else:
            return "Risk score calculated based on context-aware analysis."
