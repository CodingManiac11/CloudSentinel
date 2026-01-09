"""
Misconfiguration Data Models

Represents security misconfigurations and risk assessments.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


class Severity(str, Enum):
    """Misconfiguration severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MisconfigCategory(str, Enum):
    """Categories of misconfigurations"""
    PUBLIC_EXPOSURE = "public_exposure"
    IAM_OVERPRIVILEGE = "iam_overprivilege"
    NETWORK_SECURITY = "network_security"
    ENCRYPTION = "encryption"
    LOGGING_MONITORING = "logging_monitoring"
    KUBERNETES_SECURITY = "kubernetes_security"
    DATA_PROTECTION = "data_protection"
    COMPLIANCE = "compliance"
    AUTHENTICATION = "authentication"
    SECRETS_MANAGEMENT = "secrets_management"


class ComplianceFramework(str, Enum):
    """Compliance frameworks"""
    CIS = "cis"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    NIST = "nist"
    ISO27001 = "iso27001"


@dataclass
class RiskFactors:
    """
    Factors contributing to dynamic risk score.
    Each factor is scored 0-1.
    """
    asset_criticality: float = 0.5
    data_sensitivity: float = 0.5
    exposure_surface: float = 0.5
    blast_radius: float = 0.5
    exploit_feasibility: float = 0.5
    
    # Context-aware factors
    attack_path_position: float = 0.0  # How critical in attack chain
    compensating_controls: float = 0.0  # Mitigating factors present
    time_since_detection: float = 0.0  # Longer = higher risk
    
    def calculate_total_score(self) -> float:
        """
        Calculate weighted risk score.
        Uses a weighted formula emphasizing blast radius and exploitability.
        """
        weights = {
            "asset_criticality": 0.15,
            "data_sensitivity": 0.20,
            "exposure_surface": 0.15,
            "blast_radius": 0.20,
            "exploit_feasibility": 0.20,
            "attack_path_position": 0.10,
        }
        
        score = (
            self.asset_criticality * weights["asset_criticality"] +
            self.data_sensitivity * weights["data_sensitivity"] +
            self.exposure_surface * weights["exposure_surface"] +
            self.blast_radius * weights["blast_radius"] +
            self.exploit_feasibility * weights["exploit_feasibility"] +
            self.attack_path_position * weights["attack_path_position"]
        )
        
        # Apply compensating control reduction
        score = score * (1 - self.compensating_controls * 0.3)
        
        return min(max(score, 0.0), 1.0)


@dataclass
class RiskScore:
    """Dynamic risk score with all contributing factors"""
    score: float  # 0-100 scale
    grade: str  # A, B, C, D, F
    factors: RiskFactors
    justification: str
    
    @classmethod
    def from_factors(cls, factors: RiskFactors, justification: str = "") -> "RiskScore":
        """Create RiskScore from factors"""
        raw_score = factors.calculate_total_score() * 100
        
        if raw_score >= 90:
            grade = "F"
        elif raw_score >= 70:
            grade = "D"
        elif raw_score >= 50:
            grade = "C"
        elif raw_score >= 30:
            grade = "B"
        else:
            grade = "A"
        
        return cls(
            score=round(raw_score, 1),
            grade=grade,
            factors=factors,
            justification=justification
        )


@dataclass
class Misconfiguration:
    """
    Represents a detected security misconfiguration.
    """
    id: str
    title: str
    description: str
    severity: Severity
    category: MisconfigCategory
    
    # Resource reference
    resource_id: str
    resource_name: str
    resource_type: str
    provider: str
    
    # Risk assessment
    risk_score: Optional[RiskScore] = None
    
    # Detection details
    rule_id: str = ""
    rule_name: str = ""
    detected_at: datetime = field(default_factory=datetime.now)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Compliance mapping
    compliance_violations: List[str] = field(default_factory=list)
    
    # Context
    context: Dict[str, Any] = field(default_factory=dict)
    related_resources: List[str] = field(default_factory=list)
    attack_paths: List[str] = field(default_factory=list)  # IDs of attack paths this is part of
    
    # Status
    status: str = "open"  # open, acknowledged, in_progress, resolved, false_positive
    assigned_to: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "resource": {
                "id": self.resource_id,
                "name": self.resource_name,
                "type": self.resource_type,
                "provider": self.provider,
            },
            "risk_score": {
                "score": self.risk_score.score if self.risk_score else None,
                "grade": self.risk_score.grade if self.risk_score else None,
            },
            "rule_id": self.rule_id,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "evidence": self.evidence,
            "compliance_violations": self.compliance_violations,
            "status": self.status,
            "attack_paths": self.attack_paths,
        }


@dataclass
class AttackPathNode:
    """A node in an attack path"""
    resource_id: str
    resource_name: str
    resource_type: str
    misconfiguration_id: Optional[str] = None
    action: str = ""  # What attacker does at this step
    access_gained: str = ""  # What access is gained


@dataclass
class AttackPath:
    """
    Represents a potential attack path through the infrastructure.
    Shows how multiple misconfigurations can be chained together.
    """
    id: str
    name: str
    description: str
    
    # Path details
    nodes: List[AttackPathNode] = field(default_factory=list)
    entry_point: Optional[str] = None  # Initial access resource
    target: Optional[str] = None  # Final target (data, admin access, etc.)
    
    # Risk assessment
    total_risk_score: float = 0.0
    exploitability: str = "medium"  # low, medium, high
    impact: str = "medium"  # low, medium, high, critical
    
    # Contributing misconfigurations
    misconfiguration_ids: List[str] = field(default_factory=list)
    
    # Analysis
    attack_type: str = ""  # privilege_escalation, data_exfiltration, lateral_movement
    techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK techniques
    
    def get_path_length(self) -> int:
        """Number of hops in the attack path"""
        return len(self.nodes)
    
    def get_summary(self) -> str:
        """Human-readable summary of the attack path"""
        if not self.nodes:
            return "Empty attack path"
        
        summary_parts = []
        for i, node in enumerate(self.nodes):
            if i == 0:
                summary_parts.append(f"Start at {node.resource_name}")
            else:
                summary_parts.append(f"→ {node.action} to reach {node.resource_name}")
        
        if self.target:
            summary_parts.append(f"→ Achieve {self.target}")
        
        return " ".join(summary_parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "nodes": [
                {
                    "resource_id": n.resource_id,
                    "resource_name": n.resource_name,
                    "resource_type": n.resource_type,
                    "action": n.action,
                    "access_gained": n.access_gained,
                }
                for n in self.nodes
            ],
            "entry_point": self.entry_point,
            "target": self.target,
            "total_risk_score": self.total_risk_score,
            "exploitability": self.exploitability,
            "impact": self.impact,
            "misconfiguration_ids": self.misconfiguration_ids,
            "attack_type": self.attack_type,
            "techniques": self.techniques,
            "path_length": self.get_path_length(),
            "summary": self.get_summary(),
        }


@dataclass
class ScanResult:
    """Complete result of a security scan"""
    scan_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Scope
    provider: str = "multi-cloud"
    regions: List[str] = field(default_factory=list)
    resource_count: int = 0
    
    # Findings
    misconfigurations: List[Misconfiguration] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    
    # Statistics
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Overall assessment
    overall_risk_score: float = 0.0
    overall_grade: str = "A"
    
    def calculate_statistics(self) -> None:
        """Calculate summary statistics from findings"""
        self.critical_count = sum(1 for m in self.misconfigurations if m.severity == Severity.CRITICAL)
        self.high_count = sum(1 for m in self.misconfigurations if m.severity == Severity.HIGH)
        self.medium_count = sum(1 for m in self.misconfigurations if m.severity == Severity.MEDIUM)
        self.low_count = sum(1 for m in self.misconfigurations if m.severity == Severity.LOW)
        
        # Calculate overall risk score
        if self.misconfigurations:
            scores = [m.risk_score.score for m in self.misconfigurations if m.risk_score]
            if scores:
                # Weighted toward higher scores
                self.overall_risk_score = sum(sorted(scores, reverse=True)[:10]) / min(10, len(scores))
        
        # Assign grade
        if self.overall_risk_score >= 80:
            self.overall_grade = "F"
        elif self.overall_risk_score >= 60:
            self.overall_grade = "D"
        elif self.overall_risk_score >= 40:
            self.overall_grade = "C"
        elif self.overall_risk_score >= 20:
            self.overall_grade = "B"
        else:
            self.overall_grade = "A"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "provider": self.provider,
            "resource_count": self.resource_count,
            "findings": {
                "total": len(self.misconfigurations),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "attack_paths": len(self.attack_paths),
            "overall_risk_score": self.overall_risk_score,
            "overall_grade": self.overall_grade,
            "misconfigurations": [m.to_dict() for m in self.misconfigurations],
            "attack_paths_detail": [a.to_dict() for a in self.attack_paths],
        }
