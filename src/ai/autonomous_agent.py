"""
Autonomous Remediation Agent

AI-powered agent that can automatically fix misconfigurations with guardrails.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..models.remediation import (
    RemediationAction, RemediationRisk, GuardrailConfig,
    RemediationExecution, RemediationStatus
)
from ..models.misconfiguration import Misconfiguration, Severity


class AgentDecision(str, Enum):
    """Decisions the agent can make"""
    AUTO_REMEDIATE = "auto_remediate"
    REQUEST_APPROVAL = "request_approval"
    DEFER = "defer"
    SKIP = "skip"


@dataclass
class AgentAction:
    """An action decided by the agent"""
    decision: AgentDecision
    misconfiguration_id: str
    remediation_action: Optional[RemediationAction]
    confidence: float
    reasoning: str
    guardrail_checks: List[str]
    warnings: List[str] = field(default_factory=list)


@dataclass
class AgentSession:
    """A remediation session managed by the agent"""
    session_id: str
    started_at: datetime
    actions: List[AgentAction]
    executions: List[RemediationExecution]
    status: str  # active, completed, paused
    
    auto_remediated: int = 0
    requested_approval: int = 0
    skipped: int = 0


class AutonomousRemediationAgent:
    """
    An AI-powered agent that can automatically remediate misconfigurations
    with appropriate guardrails and human-in-the-loop for high-risk changes.
    
    Key principles:
    - Never auto-remediate high-risk changes without approval
    - Always provide rollback capability
    - Learn from remediation patterns
    - Respect organizational policies
    """
    
    def __init__(self, guardrails: GuardrailConfig = None):
        self.guardrails = guardrails or GuardrailConfig()
        self.current_session: Optional[AgentSession] = None
        self.remediation_history: List[RemediationExecution] = []
    
    def evaluate_remediation(
        self,
        misconfiguration: Misconfiguration,
        remediation: RemediationAction
    ) -> AgentAction:
        """
        Evaluate whether to auto-remediate, request approval, or skip.
        """
        guardrail_checks = []
        warnings = []
        
        # Check 1: Risk level
        can_auto_by_risk = self._check_risk_level(remediation.risk_level, guardrail_checks)
        
        # Check 2: Resource type
        can_auto_by_resource = self._check_resource_type(
            misconfiguration.resource_type, guardrail_checks
        )
        
        # Check 3: Time window
        can_auto_by_time = self._check_time_window(guardrail_checks)
        
        # Check 4: Daily limits
        can_auto_by_limits = self._check_daily_limits(guardrail_checks)
        
        # Check 5: Rollback capability
        has_rollback = remediation.rollback_plan is not None
        if not has_rollback:
            warnings.append("No rollback plan available")
        
        # Decision logic
        all_checks_pass = all([
            can_auto_by_risk,
            can_auto_by_resource,
            can_auto_by_time,
            can_auto_by_limits,
            has_rollback or remediation.risk_level == RemediationRisk.SAFE,
        ])
        
        if not self.guardrails.enable_auto_remediation:
            decision = AgentDecision.REQUEST_APPROVAL
            reasoning = "Auto-remediation is disabled; requesting manual approval"
            confidence = 1.0
        elif misconfiguration.severity in [Severity.CRITICAL, Severity.HIGH] and \
             not remediation.can_auto_remediate():
            decision = AgentDecision.REQUEST_APPROVAL
            reasoning = "High-severity issue requires human approval for remediation"
            confidence = 0.85
        elif all_checks_pass and remediation.can_auto_remediate():
            decision = AgentDecision.AUTO_REMEDIATE
            reasoning = "All guardrail checks passed; safe to auto-remediate"
            confidence = 0.9
        elif remediation.risk_level == RemediationRisk.CRITICAL:
            decision = AgentDecision.DEFER
            reasoning = "Critical risk remediation requires careful planning"
            confidence = 0.95
        else:
            decision = AgentDecision.REQUEST_APPROVAL
            reasoning = "Some guardrail checks failed; requesting approval"
            confidence = 0.8
        
        return AgentAction(
            decision=decision,
            misconfiguration_id=misconfiguration.id,
            remediation_action=remediation,
            confidence=confidence,
            reasoning=reasoning,
            guardrail_checks=guardrail_checks,
            warnings=warnings,
        )
    
    def process_batch(
        self,
        findings: List[tuple]  # List of (Misconfiguration, RemediationAction) tuples
    ) -> AgentSession:
        """
        Process a batch of misconfigurations and decide on remediation.
        """
        import uuid
        
        session = AgentSession(
            session_id=f"session-{uuid.uuid4().hex[:8]}",
            started_at=datetime.now(),
            actions=[],
            executions=[],
            status="active",
        )
        self.current_session = session
        
        for misconfiguration, remediation in findings:
            action = self.evaluate_remediation(misconfiguration, remediation)
            session.actions.append(action)
            
            # Track decision counts
            if action.decision == AgentDecision.AUTO_REMEDIATE:
                session.auto_remediated += 1
            elif action.decision == AgentDecision.REQUEST_APPROVAL:
                session.requested_approval += 1
            else:
                session.skipped += 1
        
        session.status = "completed"
        return session
    
    def execute_safe_remediations(self, session: AgentSession) -> List[RemediationExecution]:
        """
        Execute only the safe, auto-approved remediations.
        """
        import uuid
        executions = []
        
        for action in session.actions:
            if action.decision == AgentDecision.AUTO_REMEDIATE:
                execution = self._simulate_execution(action)
                executions.append(execution)
                session.executions.append(execution)
        
        return executions
    
    def _simulate_execution(self, action: AgentAction) -> RemediationExecution:
        """Simulate execution of a remediation action"""
        import uuid
        
        execution = RemediationExecution(
            id=f"exec-{uuid.uuid4().hex[:8]}",
            remediation_action_id=action.remediation_action.id if action.remediation_action else "",
            started_at=datetime.now(),
            status=RemediationStatus.IN_PROGRESS,
        )
        
        # Simulate steps
        execution.add_log("Starting automated remediation...")
        execution.add_log(f"Validating guardrail checks: {len(action.guardrail_checks)} passed")
        
        if action.remediation_action:
            for i, step in enumerate(action.remediation_action.steps[:3], 1):
                execution.add_log(f"Step {i}: {step}")
                execution.current_step = i
        
        execution.add_log("Verification: Configuration updated successfully")
        execution.complete(success=True)
        
        return execution
    
    def _check_risk_level(self, risk_level: RemediationRisk, checks: List[str]) -> bool:
        """Check if risk level allows auto-remediation"""
        risk_order = [
            RemediationRisk.SAFE, RemediationRisk.LOW,
            RemediationRisk.MEDIUM, RemediationRisk.HIGH,
            RemediationRisk.CRITICAL
        ]
        
        max_allowed = self.guardrails.max_risk_level
        if risk_order.index(risk_level) <= risk_order.index(max_allowed):
            checks.append(f"✓ Risk level ({risk_level.value}) within allowed threshold")
            return True
        else:
            checks.append(f"✗ Risk level ({risk_level.value}) exceeds threshold ({max_allowed.value})")
            return False
    
    def _check_resource_type(self, resource_type: str, checks: List[str]) -> bool:
        """Check if resource type is allowed for auto-remediation"""
        excluded = self.guardrails.excluded_resource_types
        allowed = self.guardrails.allowed_resource_types
        
        if resource_type in excluded:
            checks.append(f"✗ Resource type '{resource_type}' is excluded")
            return False
        
        if allowed and resource_type not in allowed:
            checks.append(f"✗ Resource type '{resource_type}' not in allowed list")
            return False
        
        checks.append(f"✓ Resource type '{resource_type}' is allowed")
        return True
    
    def _check_time_window(self, checks: List[str]) -> bool:
        """Check if current time is within allowed remediation window"""
        current_hour = datetime.now().hour
        current_day = datetime.now().weekday()
        
        hour_ok = self.guardrails.allowed_hours_start <= current_hour < self.guardrails.allowed_hours_end
        day_ok = current_day in self.guardrails.allowed_days
        
        if hour_ok and day_ok:
            checks.append(f"✓ Within allowed time window (hour: {current_hour})")
            return True
        else:
            checks.append(f"✗ Outside allowed time window")
            return False
    
    def _check_daily_limits(self, checks: List[str]) -> bool:
        """Check if daily remediation limits are not exceeded"""
        today_count = len([
            e for e in self.remediation_history
            if e.started_at.date() == datetime.now().date()
        ])
        
        if today_count < self.guardrails.max_daily_remediations:
            checks.append(f"✓ Daily limit not exceeded ({today_count}/{self.guardrails.max_daily_remediations})")
            return True
        else:
            checks.append(f"✗ Daily limit exceeded ({today_count}/{self.guardrails.max_daily_remediations})")
            return False
    
    def get_session_summary(self, session: AgentSession) -> Dict[str, Any]:
        """Generate summary of agent session"""
        return {
            "session_id": session.session_id,
            "started_at": session.started_at.isoformat(),
            "total_actions": len(session.actions),
            "auto_remediated": session.auto_remediated,
            "requested_approval": session.requested_approval,
            "skipped": session.skipped,
            "executions": len(session.executions),
            "success_rate": (
                sum(1 for e in session.executions if e.success) / len(session.executions)
                if session.executions else 0
            ),
            "status": session.status,
        }
