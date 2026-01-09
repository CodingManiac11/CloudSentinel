"""
Remediation Data Models

Represents remediation actions, IaC patches, and approval workflows.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


class RemediationType(str, Enum):
    """Types of remediation actions"""
    POLICY_UPDATE = "policy_update"
    CONFIGURATION_CHANGE = "configuration_change"
    NETWORK_RULE = "network_rule"
    ENCRYPTION_ENABLE = "encryption_enable"
    ACCESS_REVOKE = "access_revoke"
    RESOURCE_DELETE = "resource_delete"
    IAC_PATCH = "iac_patch"
    MANUAL = "manual"


class RemediationRisk(str, Enum):
    """Risk level of applying remediation"""
    SAFE = "safe"  # No service impact expected
    LOW = "low"  # Minor impact possible
    MEDIUM = "medium"  # Service disruption possible
    HIGH = "high"  # Significant impact likely
    CRITICAL = "critical"  # Requires careful planning


class ApprovalStatus(str, Enum):
    """Status of remediation approval"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    AUTO_APPROVED = "auto_approved"
    EXPIRED = "expired"


class RemediationStatus(str, Enum):
    """Status of remediation execution"""
    READY = "ready"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class IaCPatch:
    """
    Infrastructure as Code patch for remediation.
    Supports Terraform, CloudFormation, and Kubernetes manifests.
    """
    id: str
    format: str  # terraform, cloudformation, kubernetes, pulumi
    
    # File details
    file_path: str
    original_content: str
    patched_content: str
    diff: str
    
    # Metadata
    description: str = ""
    breaking_changes: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    def get_line_changes(self) -> Dict[str, int]:
        """Get count of lines added/removed"""
        added = self.diff.count('\n+')
        removed = self.diff.count('\n-')
        return {"added": added, "removed": removed}


@dataclass
class RollbackPlan:
    """Plan for rolling back a remediation"""
    id: str
    remediation_id: str
    
    # Rollback details
    steps: List[str] = field(default_factory=list)
    iac_patches: List[IaCPatch] = field(default_factory=list)
    
    # State backup
    original_state: Dict[str, Any] = field(default_factory=dict)
    backup_created_at: Optional[datetime] = None
    
    # Execution
    estimated_time_seconds: int = 60
    requires_downtime: bool = False
    
    def can_auto_rollback(self) -> bool:
        """Check if automatic rollback is possible"""
        return bool(self.original_state) and not self.requires_downtime


@dataclass
class RemediationAction:
    """
    A single remediation action to fix a misconfiguration.
    """
    id: str
    misconfiguration_id: str
    title: str
    description: str
    
    # Type and risk
    remediation_type: RemediationType
    risk_level: RemediationRisk
    
    # Instructions
    steps: List[str] = field(default_factory=list)
    plain_language_explanation: str = ""  # Developer-friendly explanation
    
    # Automation
    automated: bool = False
    iac_patch: Optional[IaCPatch] = None
    script: Optional[str] = None  # CLI/API commands
    
    # Dependencies
    prerequisites: List[str] = field(default_factory=list)
    dependent_actions: List[str] = field(default_factory=list)
    
    # Rollback
    rollback_plan: Optional[RollbackPlan] = None
    
    # Metadata
    estimated_time_minutes: int = 5
    requires_restart: bool = False
    affects_resources: List[str] = field(default_factory=list)
    
    # References
    documentation_url: Optional[str] = None
    best_practice_reference: Optional[str] = None
    
    def can_auto_remediate(self) -> bool:
        """Check if action can be auto-remediated"""
        return (
            self.automated and 
            self.risk_level in [RemediationRisk.SAFE, RemediationRisk.LOW] and
            not self.requires_restart
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "misconfiguration_id": self.misconfiguration_id,
            "title": self.title,
            "description": self.description,
            "type": self.remediation_type.value,
            "risk_level": self.risk_level.value,
            "steps": self.steps,
            "plain_language_explanation": self.plain_language_explanation,
            "automated": self.automated,
            "can_auto_remediate": self.can_auto_remediate(),
            "has_iac_patch": self.iac_patch is not None,
            "has_rollback": self.rollback_plan is not None,
            "estimated_time_minutes": self.estimated_time_minutes,
            "requires_restart": self.requires_restart,
        }


@dataclass
class ApprovalRequest:
    """Request for approval to execute remediation"""
    id: str
    remediation_id: str
    requested_by: str
    requested_at: datetime
    
    # Approval details
    approvers: List[str] = field(default_factory=list)
    required_approvals: int = 1
    current_approvals: int = 0
    
    # Status
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: List[str] = field(default_factory=list)
    approved_at: Optional[datetime] = None
    rejected_by: Optional[str] = None
    rejection_reason: Optional[str] = None
    
    # Expiration
    expires_at: Optional[datetime] = None
    
    # Context
    justification: str = ""
    impact_summary: str = ""
    
    def is_approved(self) -> bool:
        """Check if request is approved"""
        return self.current_approvals >= self.required_approvals


@dataclass
class RemediationExecution:
    """
    Tracks execution of a remediation action.
    """
    id: str
    remediation_action_id: str
    
    # Timing
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Status
    status: RemediationStatus = RemediationStatus.IN_PROGRESS
    progress_percent: int = 0
    current_step: int = 0
    total_steps: int = 1
    
    # Results
    success: bool = False
    error_message: Optional[str] = None
    output_log: List[str] = field(default_factory=list)
    
    # Verification
    verified: bool = False
    verification_result: Optional[Dict[str, Any]] = None
    
    # Rollback tracking
    rolled_back: bool = False
    rollback_reason: Optional[str] = None
    rollback_at: Optional[datetime] = None
    
    def add_log(self, message: str) -> None:
        """Add entry to output log"""
        timestamp = datetime.now().isoformat()
        self.output_log.append(f"[{timestamp}] {message}")
    
    def complete(self, success: bool, error: Optional[str] = None) -> None:
        """Mark execution as complete"""
        self.completed_at = datetime.now()
        self.success = success
        self.error_message = error
        self.status = RemediationStatus.COMPLETED if success else RemediationStatus.FAILED
        self.progress_percent = 100 if success else self.progress_percent


@dataclass
class RemediationPlan:
    """
    Complete remediation plan for multiple findings.
    Groups related remediations and manages execution order.
    """
    id: str
    name: str
    description: str
    created_at: datetime
    
    # Actions
    actions: List[RemediationAction] = field(default_factory=list)
    execution_order: List[str] = field(default_factory=list)  # Action IDs in order
    
    # Approval
    approval_required: bool = True
    approval_request: Optional[ApprovalRequest] = None
    
    # Status
    status: RemediationStatus = RemediationStatus.READY
    executions: List[RemediationExecution] = field(default_factory=list)
    
    # Impact
    total_affected_resources: int = 0
    estimated_downtime_minutes: int = 0
    
    def get_safe_actions(self) -> List[RemediationAction]:
        """Get actions that can be auto-remediated"""
        return [a for a in self.actions if a.can_auto_remediate()]
    
    def get_pending_actions(self) -> List[RemediationAction]:
        """Get actions not yet executed"""
        executed_ids = {e.remediation_action_id for e in self.executions}
        return [a for a in self.actions if a.id not in executed_ids]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "actions_count": len(self.actions),
            "safe_actions_count": len(self.get_safe_actions()),
            "status": self.status.value,
            "approval_required": self.approval_required,
            "actions": [a.to_dict() for a in self.actions],
            "total_affected_resources": self.total_affected_resources,
            "estimated_downtime_minutes": self.estimated_downtime_minutes,
        }


@dataclass
class GuardrailConfig:
    """
    Configuration for autonomous remediation guardrails.
    Defines what actions can be auto-executed.
    """
    # Auto-remediation settings
    enable_auto_remediation: bool = False
    max_risk_level: RemediationRisk = RemediationRisk.LOW
    
    # Scope limits
    allowed_resource_types: List[str] = field(default_factory=list)
    excluded_resource_types: List[str] = field(default_factory=list)
    allowed_regions: List[str] = field(default_factory=list)
    excluded_accounts: List[str] = field(default_factory=list)
    
    # Time windows
    allowed_hours_start: int = 9  # 9 AM
    allowed_hours_end: int = 17  # 5 PM
    allowed_days: List[int] = field(default_factory=lambda: [0, 1, 2, 3, 4])  # Mon-Fri
    
    # Limits
    max_concurrent_remediations: int = 3
    max_daily_remediations: int = 10
    cooldown_minutes: int = 30  # Between remediations on same resource
    
    # Notifications
    notify_on_auto_remediation: bool = True
    notification_channels: List[str] = field(default_factory=list)
    
    def can_auto_remediate(self, action: RemediationAction, current_hour: int = 12) -> bool:
        """Check if action passes guardrail checks"""
        if not self.enable_auto_remediation:
            return False
        
        # Check risk level
        risk_order = [RemediationRisk.SAFE, RemediationRisk.LOW, RemediationRisk.MEDIUM, 
                      RemediationRisk.HIGH, RemediationRisk.CRITICAL]
        if risk_order.index(action.risk_level) > risk_order.index(self.max_risk_level):
            return False
        
        # Check time window
        if not (self.allowed_hours_start <= current_hour < self.allowed_hours_end):
            return False
        
        return action.can_auto_remediate()
