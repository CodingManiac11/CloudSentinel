"""
Remediation Workflow

Manages approval-based and automated remediation workflows.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import uuid

from ..models.remediation import (
    RemediationPlan, RemediationAction, RemediationExecution,
    ApprovalRequest, ApprovalStatus, RemediationStatus, RollbackPlan
)


class WorkflowState(str, Enum):
    """States of the remediation workflow"""
    CREATED = "created"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass
class WorkflowNotification:
    """A notification about workflow status"""
    id: str
    workflow_id: str
    timestamp: datetime
    event_type: str
    message: str
    recipients: List[str]


class RemediationWorkflow:
    """
    Manages the complete remediation workflow including:
    - Creating remediation plans
    - Managing approvals
    - Executing remediations
    - Handling rollbacks
    """
    
    def __init__(self):
        self.plans: Dict[str, RemediationPlan] = {}
        self.approvals: Dict[str, ApprovalRequest] = {}
        self.notifications: List[WorkflowNotification] = []
    
    def create_plan(
        self,
        name: str,
        actions: List[RemediationAction],
        require_approval: bool = True
    ) -> RemediationPlan:
        """
        Create a new remediation plan.
        """
        plan_id = f"plan-{uuid.uuid4().hex[:8]}"
        
        # Determine execution order (simple: by risk level, safe first)
        risk_order = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        sorted_actions = sorted(actions, key=lambda a: risk_order.get(a.risk_level.value, 2))
        
        plan = RemediationPlan(
            id=plan_id,
            name=name,
            description=f"Remediation plan for {len(actions)} issues",
            created_at=datetime.now(),
            actions=sorted_actions,
            execution_order=[a.id for a in sorted_actions],
            approval_required=require_approval,
            status=RemediationStatus.READY,
            total_affected_resources=len(set(a.misconfiguration_id for a in actions)),
        )
        
        self.plans[plan_id] = plan
        
        # Create approval request if required
        if require_approval:
            self._create_approval_request(plan)
        
        return plan
    
    def request_approval(
        self,
        plan_id: str,
        approvers: List[str],
        justification: str = ""
    ) -> ApprovalRequest:
        """
        Create an approval request for a plan.
        """
        plan = self.plans.get(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")
        
        request = ApprovalRequest(
            id=f"approval-{uuid.uuid4().hex[:8]}",
            remediation_id=plan_id,
            requested_by="system",
            requested_at=datetime.now(),
            approvers=approvers,
            required_approvals=1,
            expires_at=datetime.now() + timedelta(hours=24),
            justification=justification,
            impact_summary=f"{len(plan.actions)} remediations affecting {plan.total_affected_resources} resources",
        )
        
        self.approvals[request.id] = request
        plan.approval_request = request
        plan.status = RemediationStatus.PENDING_APPROVAL
        
        # Send notification
        self._notify(
            plan_id,
            "approval_requested",
            f"Approval requested for remediation plan '{plan.name}'",
            approvers
        )
        
        return request
    
    def approve(
        self,
        approval_id: str,
        approver: str,
        comment: str = ""
    ) -> bool:
        """
        Approve a remediation request.
        """
        request = self.approvals.get(approval_id)
        if not request:
            return False
        
        if request.status != ApprovalStatus.PENDING:
            return False
        
        request.approved_by.append(approver)
        request.current_approvals += 1
        
        if request.is_approved():
            request.status = ApprovalStatus.APPROVED
            request.approved_at = datetime.now()
            
            # Update plan status
            plan = self.plans.get(request.remediation_id)
            if plan:
                plan.status = RemediationStatus.APPROVED
            
            self._notify(
                request.remediation_id,
                "approved",
                f"Remediation plan approved by {approver}",
                []
            )
        
        return True
    
    def reject(
        self,
        approval_id: str,
        rejector: str,
        reason: str
    ) -> bool:
        """
        Reject a remediation request.
        """
        request = self.approvals.get(approval_id)
        if not request:
            return False
        
        request.status = ApprovalStatus.REJECTED
        request.rejected_by = rejector
        request.rejection_reason = reason
        
        # Update plan status
        plan = self.plans.get(request.remediation_id)
        if plan:
            plan.status = RemediationStatus.READY
        
        self._notify(
            request.remediation_id,
            "rejected",
            f"Remediation plan rejected by {rejector}: {reason}",
            []
        )
        
        return True
    
    def execute_plan(self, plan_id: str) -> List[RemediationExecution]:
        """
        Execute a remediation plan.
        """
        plan = self.plans.get(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")
        
        if plan.approval_required and plan.status != RemediationStatus.APPROVED:
            raise ValueError("Plan requires approval before execution")
        
        plan.status = RemediationStatus.IN_PROGRESS
        executions = []
        
        for action_id in plan.execution_order:
            action = next((a for a in plan.actions if a.id == action_id), None)
            if not action:
                continue
            
            execution = self._execute_action(action)
            executions.append(execution)
            plan.executions.append(execution)
            
            # Stop on failure for safety
            if not execution.success:
                plan.status = RemediationStatus.FAILED
                self._notify(
                    plan_id,
                    "execution_failed",
                    f"Remediation failed at step: {action.title}",
                    []
                )
                break
        
        if all(e.success for e in executions):
            plan.status = RemediationStatus.COMPLETED
            self._notify(
                plan_id,
                "completed",
                f"Remediation plan completed successfully: {len(executions)} actions",
                []
            )
        
        return executions
    
    def rollback(self, plan_id: str, reason: str = "") -> bool:
        """
        Rollback a remediation plan.
        """
        plan = self.plans.get(plan_id)
        if not plan:
            return False
        
        # Check for rollback capability
        rollbackable = [
            e for e in plan.executions 
            if e.success and not e.rolled_back
        ]
        
        if not rollbackable:
            return False
        
        for execution in reversed(rollbackable):
            execution.rolled_back = True
            execution.rollback_reason = reason
            execution.rollback_at = datetime.now()
        
        plan.status = RemediationStatus.ROLLED_BACK
        
        self._notify(
            plan_id,
            "rolled_back",
            f"Remediation plan rolled back: {reason}",
            []
        )
        
        return True
    
    def get_plan_status(self, plan_id: str) -> Dict[str, Any]:
        """Get current status of a plan"""
        plan = self.plans.get(plan_id)
        if not plan:
            return {"error": "Plan not found"}
        
        return {
            "plan_id": plan.id,
            "name": plan.name,
            "status": plan.status.value,
            "total_actions": len(plan.actions),
            "executed": len(plan.executions),
            "successful": sum(1 for e in plan.executions if e.success),
            "failed": sum(1 for e in plan.executions if not e.success),
            "approval_status": plan.approval_request.status.value if plan.approval_request else "not_required",
            "created_at": plan.created_at.isoformat(),
        }
    
    def _create_approval_request(self, plan: RemediationPlan) -> ApprovalRequest:
        """Create an approval request for a plan"""
        request = ApprovalRequest(
            id=f"approval-{uuid.uuid4().hex[:8]}",
            remediation_id=plan.id,
            requested_by="system",
            requested_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=24),
        )
        
        self.approvals[request.id] = request
        plan.approval_request = request
        return request
    
    def _execute_action(self, action: RemediationAction) -> RemediationExecution:
        """Execute a single remediation action"""
        execution = RemediationExecution(
            id=f"exec-{uuid.uuid4().hex[:8]}",
            remediation_action_id=action.id,
            started_at=datetime.now(),
            total_steps=len(action.steps),
        )
        
        # Simulate execution
        execution.add_log(f"Starting: {action.title}")
        
        for i, step in enumerate(action.steps, 1):
            execution.current_step = i
            execution.progress_percent = int((i / len(action.steps)) * 100)
            execution.add_log(f"Step {i}: {step}")
        
        # Simulate success
        execution.complete(success=True)
        execution.add_log("Verification passed")
        
        return execution
    
    def _notify(
        self,
        workflow_id: str,
        event_type: str,
        message: str,
        recipients: List[str]
    ) -> None:
        """Create a notification"""
        notification = WorkflowNotification(
            id=f"notif-{uuid.uuid4().hex[:8]}",
            workflow_id=workflow_id,
            timestamp=datetime.now(),
            event_type=event_type,
            message=message,
            recipients=recipients,
        )
        self.notifications.append(notification)
