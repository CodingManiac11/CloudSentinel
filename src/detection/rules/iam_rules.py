"""
IAM Misconfiguration Detection Rules

Detects over-permissive IAM policies and risky identity configurations.
"""

from typing import Dict, Optional, Any, List

from .base_rule import BaseDetectionRule, RuleMetadata, register_rule
from ...models.cloud_resource import CloudResource, ResourceType, CloudProvider
from ...models.misconfiguration import Misconfiguration, Severity, MisconfigCategory


class OverprivilegedIAMRoleRule(BaseDetectionRule):
    """Detects IAM roles with overly broad permissions"""
    
    DANGEROUS_POLICIES = [
        "AdministratorAccess",
        "PowerUserAccess",
        "IAMFullAccess",
    ]
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="overprivileged-iam-role",
            name="Over-Privileged IAM Role",
            description="IAM role has excessively broad permissions that violate least privilege",
            severity=Severity.HIGH,
            category=MisconfigCategory.IAM_OVERPRIVILEGE,
            resource_types=[ResourceType.IAM_ROLE],
            providers=[CloudProvider.AWS],
            compliance_controls=["CIS-AWS-1.16", "SOC2-CC6.3", "NIST-AC-6"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        attached_policies = config.get("attached_policies", [])
        inline_policies = config.get("inline_policies", {})
        
        issues = []
        
        # Check for dangerous managed policies
        for policy_arn in attached_policies:
            for dangerous in self.DANGEROUS_POLICIES:
                if dangerous in policy_arn:
                    issues.append(f"Has {dangerous} policy attached")
        
        # Check for wildcard permissions in inline policies
        for policy_name, policy_doc in inline_policies.items():
            for statement in policy_doc.get("Statement", []):
                action = statement.get("Action", [])
                resource_pattern = statement.get("Resource", [])
                
                if action == "*" or (isinstance(action, list) and "*" in action):
                    issues.append(f"Policy '{policy_name}' allows all actions (*)")
                
                if isinstance(action, str) and action.endswith(":*"):
                    issues.append(f"Policy '{policy_name}' allows all {action.split(':')[0]} actions")
                
                if resource_pattern == "*" or (isinstance(resource_pattern, list) and "*" in resource_pattern):
                    issues.append(f"Policy '{policy_name}' applies to all resources (*)")
        
        if issues:
            return self.create_misconfiguration(
                resource=resource,
                title=f"IAM Role '{resource.name}' has excessive permissions",
                description=(
                    f"The IAM role '{resource.name}' violates the principle of least privilege. "
                    f"Issues found: {'; '.join(issues[:3])}. "
                    f"Over-privileged roles can lead to privilege escalation if compromised."
                ),
                evidence={
                    "issues": issues,
                    "attached_policies": attached_policies,
                    "has_inline_policies": len(inline_policies) > 0,
                }
            )
        
        return None


class IAMUserWithoutMFARule(BaseDetectionRule):
    """Detects IAM users without MFA enabled"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="iam-user-no-mfa",
            name="IAM User Without MFA",
            description="IAM user does not have multi-factor authentication enabled",
            severity=Severity.HIGH,
            category=MisconfigCategory.AUTHENTICATION,
            resource_types=[ResourceType.IAM_USER],
            providers=[CloudProvider.AWS],
            compliance_controls=["CIS-AWS-1.10", "SOC2-CC6.1", "PCI-DSS-8.4.1"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        if not config.get("mfa_enabled", False) and not resource.config.mfa_enabled:
            # Check if user has console access or access keys
            has_console_access = config.get("console_access", False)
            access_keys = config.get("access_keys", [])
            has_active_keys = any(k.get("status") == "Active" for k in access_keys)
            
            if has_console_access or has_active_keys:
                return self.create_misconfiguration(
                    resource=resource,
                    title=f"IAM User '{resource.name}' does not have MFA enabled",
                    description=(
                        f"The IAM user '{resource.name}' does not have MFA enabled. "
                        f"This user has {'console access' if has_console_access else 'active access keys'}. "
                        f"Without MFA, the account is vulnerable to credential theft attacks."
                    ),
                    evidence={
                        "mfa_enabled": False,
                        "has_console_access": has_console_access,
                        "has_active_access_keys": has_active_keys,
                    }
                )
        
        return None


class OldAccessKeysRule(BaseDetectionRule):
    """Detects IAM users with old access keys"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="old-access-keys",
            name="Stale Access Keys",
            description="IAM user has access keys older than 90 days",
            severity=Severity.MEDIUM,
            category=MisconfigCategory.IAM_OVERPRIVILEGE,
            resource_types=[ResourceType.IAM_USER],
            providers=[CloudProvider.AWS],
            compliance_controls=["CIS-AWS-1.12", "SOC2-CC6.2"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        access_keys = config.get("access_keys", [])
        
        old_keys = []
        from datetime import datetime, timedelta
        
        for key in access_keys:
            if key.get("status") == "Active":
                # Parse the date (simplified check)
                created_date = key.get("created_date", "")
                if created_date:
                    try:
                        created = datetime.strptime(created_date, "%Y-%m-%d")
                        if datetime.now() - created > timedelta(days=90):
                            old_keys.append({
                                "key_id": key.get("key_id", "")[:10] + "...",
                                "created": created_date,
                                "age_days": (datetime.now() - created).days
                            })
                    except ValueError:
                        pass
        
        if old_keys:
            return self.create_misconfiguration(
                resource=resource,
                title=f"IAM User '{resource.name}' has stale access keys",
                description=(
                    f"The IAM user '{resource.name}' has {len(old_keys)} access key(s) "
                    f"older than 90 days. Old access keys should be rotated regularly "
                    f"to minimize the risk of compromised credentials."
                ),
                evidence={
                    "old_keys": old_keys,
                    "recommendation": "Rotate access keys every 90 days",
                }
            )
        
        return None


class ServiceAccountOverprivilegedRule(BaseDetectionRule):
    """Detects Kubernetes service accounts with excessive permissions"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="k8s-overprivileged-sa",
            name="Over-Privileged Kubernetes RBAC",
            description="Kubernetes RBAC grants excessive cluster permissions",
            severity=Severity.HIGH,
            category=MisconfigCategory.IAM_OVERPRIVILEGE,
            resource_types=[ResourceType.KUBERNETES_RBAC],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-5.1.5", "NSA-CISA-K8s-1.0"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        rules = config.get("rules", [])
        
        dangerous_perms = []
        
        for rule in rules:
            api_groups = rule.get("api_groups", [])
            resources = rule.get("resources", [])
            verbs = rule.get("verbs", [])
            
            # Check for wildcard access
            if "*" in api_groups and "*" in resources and "*" in verbs:
                dangerous_perms.append("Full cluster admin access (*/*/*)") 
            elif "*" in verbs:
                dangerous_perms.append(f"All operations on {resources}")
            elif "create" in verbs and "secrets" in resources:
                dangerous_perms.append("Can create secrets")
            elif "escalate" in verbs or "impersonate" in verbs:
                dangerous_perms.append(f"Privilege escalation: {verbs}")
        
        if dangerous_perms:
            return self.create_misconfiguration(
                resource=resource,
                title=f"RBAC '{resource.name}' grants excessive permissions",
                description=(
                    f"The Kubernetes RBAC configuration '{resource.name}' grants dangerous permissions: "
                    f"{'; '.join(dangerous_perms)}. "
                    f"This could allow privilege escalation within the cluster."
                ),
                evidence={
                    "dangerous_permissions": dangerous_perms,
                    "rules": rules,
                }
            )
        
        return None


# Register rules
register_rule(OverprivilegedIAMRoleRule())
register_rule(IAMUserWithoutMFARule())
register_rule(OldAccessKeysRule())
register_rule(ServiceAccountOverprivilegedRule())
