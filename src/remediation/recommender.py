"""
Remediation Recommender

Generates developer-friendly remediation recommendations.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import uuid

from ..models.misconfiguration import Misconfiguration, MisconfigCategory, Severity
from ..models.remediation import RemediationAction, RemediationType, RemediationRisk


@dataclass
class RemediationGuidance:
    """Complete guidance for remediating an issue"""
    misconfiguration_id: str
    
    # Plain language
    what_is_wrong: str
    why_it_matters: str
    how_to_fix: str
    
    # Technical
    remediation_action: RemediationAction
    
    # Context
    estimated_effort: str
    potential_impact: str
    rollback_available: bool


class RemediationRecommender:
    """
    Generates developer-friendly remediation recommendations.
    
    Key principles:
    - Explain in plain language (not security jargon)
    - Provide step-by-step instructions
    - Include code examples when possible
    - Estimate effort and risk
    """
    
    def __init__(self):
        # Pre-defined remediation templates by category
        self.remediation_templates = self._init_templates()
    
    def recommend(self, misconfiguration: Misconfiguration) -> RemediationGuidance:
        """
        Generate remediation recommendation for a misconfiguration.
        """
        # Get template-based parts
        template = self._get_template(misconfiguration)
        
        # Generate action
        action = self._create_remediation_action(misconfiguration, template)
        
        return RemediationGuidance(
            misconfiguration_id=misconfiguration.id,
            what_is_wrong=template["what_is_wrong"].format(
                resource=misconfiguration.resource_name
            ),
            why_it_matters=template["why_it_matters"],
            how_to_fix=template["how_to_fix"].format(
                resource=misconfiguration.resource_name
            ),
            remediation_action=action,
            estimated_effort=self._estimate_effort(misconfiguration),
            potential_impact=self._assess_impact(misconfiguration),
            rollback_available=action.rollback_plan is not None,
        )
    
    def recommend_batch(
        self,
        misconfigurations: List[Misconfiguration]
    ) -> List[RemediationGuidance]:
        """Generate recommendations for multiple misconfigurations"""
        return [self.recommend(m) for m in misconfigurations]
    
    def _init_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize remediation templates"""
        return {
            "public_s3_bucket": {
                "what_is_wrong": "The S3 bucket '{resource}' is publicly accessible to anyone on the internet.",
                "why_it_matters": (
                    "Public S3 buckets are a leading cause of data breaches. "
                    "Anyone can potentially download or list the contents of this bucket."
                ),
                "how_to_fix": (
                    "1. Go to S3 console and select '{resource}'\n"
                    "2. Go to 'Permissions' tab\n"
                    "3. Click 'Block public access' and enable all options\n"
                    "4. Review and update the bucket policy to remove public access"
                ),
                "steps": [
                    "Enable S3 Block Public Access",
                    "Review bucket policy",
                    "Remove any Principal: * statements",
                    "Verify access is restricted"
                ],
                "type": RemediationType.POLICY_UPDATE,
                "risk": RemediationRisk.LOW,
            },
            "public_database": {
                "what_is_wrong": "The database '{resource}' is accessible from the public internet.",
                "why_it_matters": (
                    "Publicly accessible databases are prime targets for attackers. "
                    "They can be brute-forced, exploited for vulnerabilities, or have data exfiltrated."
                ),
                "how_to_fix": (
                    "1. Disable 'Publicly accessible' option in database settings\n"
                    "2. Update security groups to remove 0.0.0.0/0 access\n"
                    "3. Access the database through a bastion host or VPN\n"
                    "4. Enable SSL for all connections"
                ),
                "steps": [
                    "Disable public accessibility",
                    "Update security group rules",
                    "Set up VPN or bastion access",
                    "Enable SSL/TLS encryption"
                ],
                "type": RemediationType.CONFIGURATION_CHANGE,
                "risk": RemediationRisk.MEDIUM,
            },
            "overprivileged_iam": {
                "what_is_wrong": "The IAM role '{resource}' has more permissions than needed.",
                "why_it_matters": (
                    "Over-permissive roles violate the principle of least privilege. "
                    "If this role is compromised, an attacker gains broad access to your environment."
                ),
                "how_to_fix": (
                    "1. Use IAM Access Analyzer to identify used permissions\n"
                    "2. Create a new policy with only necessary permissions\n"
                    "3. Attach the new policy and remove AdministratorAccess\n"
                    "4. Test thoroughly before removing old permissions"
                ),
                "steps": [
                    "Analyze actual permission usage",
                    "Create least-privilege policy",
                    "Replace overly permissive policies",
                    "Test and validate access"
                ],
                "type": RemediationType.POLICY_UPDATE,
                "risk": RemediationRisk.MEDIUM,
            },
            "no_encryption": {
                "what_is_wrong": "The resource '{resource}' does not have encryption enabled.",
                "why_it_matters": (
                    "Data at rest should be encrypted to protect against unauthorized access "
                    "in case of storage theft or improper disposal."
                ),
                "how_to_fix": (
                    "1. Enable encryption in the resource settings\n"
                    "2. Choose a customer-managed key for better control\n"
                    "3. Enable automatic key rotation\n"
                    "4. Verify encryption status after enabling"
                ),
                "steps": [
                    "Enable encryption at rest",
                    "Configure encryption key",
                    "Enable key rotation",
                    "Verify encryption status"
                ],
                "type": RemediationType.ENCRYPTION_ENABLE,
                "risk": RemediationRisk.SAFE,
            },
            "open_security_group": {
                "what_is_wrong": "The security group for '{resource}' allows unrestricted access from the internet.",
                "why_it_matters": (
                    "Open security groups expose your resources to attacks from any IP address. "
                    "This significantly increases your attack surface."
                ),
                "how_to_fix": (
                    "1. Identify the legitimate IP ranges that need access\n"
                    "2. Update inbound rules to restrict to those IPs only\n"
                    "3. Remove any 0.0.0.0/0 rules for sensitive ports\n"
                    "4. Use security groups for internal traffic instead of IP ranges"
                ),
                "steps": [
                    "Audit current inbound rules",
                    "Identify required source IPs",
                    "Restrict rules to specific CIDRs",
                    "Test connectivity"
                ],
                "type": RemediationType.NETWORK_RULE,
                "risk": RemediationRisk.MEDIUM,
            },
            "privileged_container": {
                "what_is_wrong": "Containers in '{resource}' run with elevated privileges.",
                "why_it_matters": (
                    "Privileged containers have full access to the host system. "
                    "If compromised, an attacker can escape the container and control the node."
                ),
                "how_to_fix": (
                    "1. Update the pod/deployment spec security context\n"
                    "2. Set privileged: false\n"
                    "3. Set allowPrivilegeEscalation: false\n"
                    "4. Define specific capabilities if needed instead of full privilege"
                ),
                "steps": [
                    "Update security context",
                    "Disable privileged mode",
                    "Block privilege escalation",
                    "Drop unnecessary capabilities"
                ],
                "type": RemediationType.IAC_PATCH,
                "risk": RemediationRisk.LOW,
            },
            "default": {
                "what_is_wrong": "The resource '{resource}' has a security misconfiguration.",
                "why_it_matters": (
                    "Security misconfigurations can expose your resources to attacks "
                    "and may violate compliance requirements."
                ),
                "how_to_fix": (
                    "1. Review the detected issue details\n"
                    "2. Consult the security best practices documentation\n"
                    "3. Apply the recommended configuration change\n"
                    "4. Verify the fix was applied correctly"
                ),
                "steps": [
                    "Review issue details",
                    "Plan remediation",
                    "Apply fix",
                    "Verify resolution"
                ],
                "type": RemediationType.CONFIGURATION_CHANGE,
                "risk": RemediationRisk.MEDIUM,
            }
        }
    
    def _get_template(self, misc: Misconfiguration) -> Dict[str, Any]:
        """Get the appropriate template for a misconfiguration"""
        title_lower = misc.title.lower()
        
        if "s3" in title_lower and "public" in title_lower:
            return self.remediation_templates["public_s3_bucket"]
        if "database" in title_lower and "public" in title_lower:
            return self.remediation_templates["public_database"]
        if "privilege" in title_lower and ("iam" in title_lower or "role" in title_lower):
            return self.remediation_templates["overprivileged_iam"]
        if "encrypt" in title_lower and "not" in title_lower:
            return self.remediation_templates["no_encryption"]
        if "security group" in title_lower or "unrestricted" in title_lower:
            return self.remediation_templates["open_security_group"]
        if "privileged" in title_lower and "container" in title_lower:
            return self.remediation_templates["privileged_container"]
        
        return self.remediation_templates["default"]
    
    def _create_remediation_action(
        self,
        misc: Misconfiguration,
        template: Dict[str, Any]
    ) -> RemediationAction:
        """Create a remediation action from template"""
        return RemediationAction(
            id=f"rem-{uuid.uuid4().hex[:8]}",
            misconfiguration_id=misc.id,
            title=f"Fix: {misc.title}",
            description=template["what_is_wrong"].format(resource=misc.resource_name),
            remediation_type=template["type"],
            risk_level=template["risk"],
            steps=template["steps"],
            plain_language_explanation=template["how_to_fix"].format(resource=misc.resource_name),
            automated=template["risk"] in [RemediationRisk.SAFE, RemediationRisk.LOW],
            estimated_time_minutes=self._estimate_minutes(misc),
        )
    
    def _estimate_effort(self, misc: Misconfiguration) -> str:
        """Estimate the effort required to fix"""
        category = misc.category
        
        quick_fix = [MisconfigCategory.ENCRYPTION, MisconfigCategory.LOGGING_MONITORING]
        medium_fix = [MisconfigCategory.NETWORK_SECURITY, MisconfigCategory.AUTHENTICATION]
        complex_fix = [MisconfigCategory.IAM_OVERPRIVILEGE, MisconfigCategory.PUBLIC_EXPOSURE]
        
        if category in quick_fix:
            return "Quick fix (5-10 minutes)"
        elif category in medium_fix:
            return "Medium effort (15-30 minutes)"
        elif category in complex_fix:
            return "Requires planning (30-60 minutes)"
        return "Varies based on configuration"
    
    def _estimate_minutes(self, misc: Misconfiguration) -> int:
        """Estimate minutes to fix"""
        severity_times = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 20,
            Severity.MEDIUM: 15,
            Severity.LOW: 10,
        }
        return severity_times.get(misc.severity, 15)
    
    def _assess_impact(self, misc: Misconfiguration) -> str:
        """Assess the potential impact of remediation"""
        category = misc.category
        
        if category == MisconfigCategory.NETWORK_SECURITY:
            return "May affect connectivity - test access after applying"
        if category == MisconfigCategory.IAM_OVERPRIVILEGE:
            return "May affect application functionality - test thoroughly"
        if category == MisconfigCategory.ENCRYPTION:
            return "Generally safe - minimal application impact"
        if category == MisconfigCategory.PUBLIC_EXPOSURE:
            return "May require updating access patterns for legitimate users"
        
        return "Review application dependencies before applying"
