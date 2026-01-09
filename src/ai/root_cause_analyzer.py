"""
Root Cause Analyzer

AI-powered analysis to identify why misconfigurations occur.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class RootCauseCategory(str, Enum):
    """Categories of root causes"""
    PROCESS = "process"
    AUTOMATION = "automation"
    TRAINING = "training"
    TOOLING = "tooling"
    POLICY = "policy"
    EMERGENCY_CHANGE = "emergency_change"
    UNKNOWN = "unknown"


@dataclass
class RootCause:
    """Identified root cause of a misconfiguration"""
    id: str
    category: RootCauseCategory
    title: str
    description: str
    confidence: float
    
    affected_resources: List[str]
    related_misconfigurations: List[str]
    
    # Attribution
    likely_origin: str  # e.g., "manual change", "automation gap"
    team_pattern: Optional[str] = None
    time_pattern: Optional[str] = None
    
    # Recommendations
    prevention_recommendations: List[str] = None
    detection_recommendations: List[str] = None


@dataclass
class RootCauseAnalysis:
    """Complete root cause analysis for an environment"""
    analysis_id: str
    timestamp: datetime
    root_causes: List[RootCause]
    summary: Dict[str, Any]
    systemic_issues: List[str]


class RootCauseAnalyzer:
    """
    Analyzes patterns across misconfigurations to identify root causes.
    
    Instead of just showing WHAT is wrong, we explain WHY it happened
    and HOW to prevent it from recurring.
    """
    
    def __init__(self):
        # Common patterns that indicate root causes
        self.pattern_indicators = {
            RootCauseCategory.PROCESS: [
                "no_iac_tags",
                "inconsistent_naming",
                "missing_documentation",
            ],
            RootCauseCategory.AUTOMATION: [
                "drift_detected",
                "partial_configuration",
                "default_values",
            ],
            RootCauseCategory.TRAINING: [
                "basic_security_violations",
                "common_mistakes",
                "repeated_issues",
            ],
            RootCauseCategory.TOOLING: [
                "tool_defaults",
                "missing_enforcement",
                "no_scanning",
            ],
        }
    
    def analyze(
        self,
        misconfigurations: List[Any],  # List of Misconfiguration objects
        resources: List[Any] = None,  # List of CloudResource objects
    ) -> RootCauseAnalysis:
        """
        Perform root cause analysis on detected misconfigurations.
        """
        import uuid
        
        root_causes = []
        
        # Analyze by category patterns
        root_causes.extend(self._analyze_process_issues(misconfigurations, resources))
        root_causes.extend(self._analyze_automation_gaps(misconfigurations, resources))
        root_causes.extend(self._analyze_training_needs(misconfigurations))
        root_causes.extend(self._analyze_tooling_gaps(misconfigurations, resources))
        
        # Identify systemic issues
        systemic_issues = self._identify_systemic_issues(root_causes, misconfigurations)
        
        # Generate summary
        summary = self._generate_summary(root_causes, misconfigurations)
        
        return RootCauseAnalysis(
            analysis_id=f"rca-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(),
            root_causes=root_causes,
            summary=summary,
            systemic_issues=systemic_issues,
        )
    
    def _analyze_process_issues(
        self,
        misconfigurations: List[Any],
        resources: List[Any] = None
    ) -> List[RootCause]:
        """Identify process-related root causes"""
        import uuid
        root_causes = []
        
        if not resources:
            return root_causes
        
        # Check for IaC management gaps
        non_iac_resources = []
        for resource in resources:
            tags = resource.metadata.tags
            has_iac = any(
                key.lower() in ["terraform", "cloudformation", "pulumi", "managed-by"]
                for key in tags.keys()
            )
            if not has_iac:
                non_iac_resources.append(resource.id)
        
        if len(non_iac_resources) >= 3:
            root_causes.append(RootCause(
                id=f"rc-{uuid.uuid4().hex[:8]}",
                category=RootCauseCategory.PROCESS,
                title="Infrastructure Not Managed as Code",
                description=(
                    f"Found {len(non_iac_resources)} resources that appear to be manually "
                    f"managed rather than through Infrastructure as Code. This leads to "
                    f"configuration drift and inconsistent security settings."
                ),
                confidence=0.8,
                affected_resources=non_iac_resources[:10],
                related_misconfigurations=[m.id for m in misconfigurations[:5]],
                likely_origin="Manual provisioning/configuration",
                prevention_recommendations=[
                    "Adopt Infrastructure as Code for all resources",
                    "Implement GitOps workflow for deployments",
                    "Set up drift detection in CI/CD pipeline",
                ],
                detection_recommendations=[
                    "Tag all IaC-managed resources automatically",
                    "Alert on resources created outside IaC",
                ],
            ))
        
        return root_causes
    
    def _analyze_automation_gaps(
        self,
        misconfigurations: List[Any],
        resources: List[Any] = None
    ) -> List[RootCause]:
        """Identify automation-related root causes"""
        import uuid
        root_causes = []
        
        # Check for default value issues
        default_value_issues = [
            m for m in misconfigurations
            if "default" in m.description.lower() or "not configured" in m.description.lower()
        ]
        
        if len(default_value_issues) >= 2:
            root_causes.append(RootCause(
                id=f"rc-{uuid.uuid4().hex[:8]}",
                category=RootCauseCategory.AUTOMATION,
                title="Secure Defaults Not Enforced",
                description=(
                    f"Found {len(default_value_issues)} misconfigurations related to insecure "
                    f"default values. Automation should enforce secure defaults at provisioning time."
                ),
                confidence=0.75,
                affected_resources=[m.resource_id for m in default_value_issues],
                related_misconfigurations=[m.id for m in default_value_issues],
                likely_origin="Incomplete automation/IaC templates",
                prevention_recommendations=[
                    "Create hardened IaC modules with secure defaults",
                    "Implement policy-as-code to enforce security settings",
                    "Add pre-deployment security validation",
                ],
                detection_recommendations=[
                    "Scan IaC templates for missing security configurations",
                    "Add CI/CD checks for required security settings",
                ],
            ))
        
        return root_causes
    
    def _analyze_training_needs(self, misconfigurations: List[Any]) -> List[RootCause]:
        """Identify training-related root causes"""
        import uuid
        root_causes = []
        
        # Check for basic security mistakes that indicate training gaps
        basic_issues = {
            "public_access": 0,
            "no_encryption": 0,
            "no_mfa": 0,
            "overprivilege": 0,
        }
        
        for m in misconfigurations:
            title_lower = m.title.lower()
            if "public" in title_lower:
                basic_issues["public_access"] += 1
            if "encrypt" in title_lower:
                basic_issues["no_encryption"] += 1
            if "mfa" in title_lower:
                basic_issues["no_mfa"] += 1
            if "privilege" in title_lower or "permission" in title_lower:
                basic_issues["overprivilege"] += 1
        
        total_basic = sum(basic_issues.values())
        if total_basic >= 3:
            root_causes.append(RootCause(
                id=f"rc-{uuid.uuid4().hex[:8]}",
                category=RootCauseCategory.TRAINING,
                title="Cloud Security Fundamentals Training Gap",
                description=(
                    f"Found {total_basic} basic security misconfigurations that indicate "
                    f"a need for improved cloud security training. Common issues include: "
                    f"public exposure ({basic_issues['public_access']}), "
                    f"missing encryption ({basic_issues['no_encryption']}), "
                    f"over-privileged access ({basic_issues['overprivilege']})."
                ),
                confidence=0.7,
                affected_resources=[],
                related_misconfigurations=[m.id for m in misconfigurations],
                likely_origin="Knowledge gaps in development/operations teams",
                team_pattern="Cross-team issue",
                prevention_recommendations=[
                    "Implement mandatory cloud security training",
                    "Create and distribute secure architecture guidelines",
                    "Establish security champions in each team",
                    "Add security review to change approval process",
                ],
                detection_recommendations=[
                    "Track misconfiguration patterns by team",
                    "Measure improvement in security posture over time",
                ],
            ))
        
        return root_causes
    
    def _analyze_tooling_gaps(
        self,
        misconfigurations: List[Any],
        resources: List[Any] = None
    ) -> List[RootCause]:
        """Identify tooling-related root causes"""
        import uuid
        root_causes = []
        
        if not resources:
            return root_causes
        
        # Check for missing security tooling
        resources_without_logging = [
            r for r in resources if not r.config.logging_enabled
        ]
        
        if len(resources_without_logging) >= 3:
            root_causes.append(RootCause(
                id=f"rc-{uuid.uuid4().hex[:8]}",
                category=RootCauseCategory.TOOLING,
                title="Security Monitoring and Logging Gaps",
                description=(
                    f"Found {len(resources_without_logging)} resources without logging enabled. "
                    f"Without proper monitoring, security issues cannot be detected quickly."
                ),
                confidence=0.85,
                affected_resources=[r.id for r in resources_without_logging[:10]],
                related_misconfigurations=[],
                likely_origin="Missing centralized logging/monitoring strategy",
                prevention_recommendations=[
                    "Implement centralized logging solution",
                    "Enable CloudTrail/Activity logging for all accounts",
                    "Set up automated log analysis and alerting",
                ],
                detection_recommendations=[
                    "Create dashboard for logging coverage",
                    "Alert when new resources lack logging",
                ],
            ))
        
        return root_causes
    
    def _identify_systemic_issues(
        self,
        root_causes: List[RootCause],
        misconfigurations: List[Any]
    ) -> List[str]:
        """Identify systemic/organizational issues"""
        systemic = []
        
        category_counts = {}
        for rc in root_causes:
            cat = rc.category.value
            if cat not in category_counts:
                category_counts[cat] = 0
            category_counts[cat] += 1
        
        if category_counts.get("process", 0) >= 2:
            systemic.append(
                "Multiple process gaps suggest need for a comprehensive security governance review"
            )
        
        if category_counts.get("training", 0) >= 1 and len(misconfigurations) > 10:
            systemic.append(
                "High volume of basic misconfigurations indicates organization-wide security awareness gap"
            )
        
        if category_counts.get("automation", 0) >= 1 and category_counts.get("tooling", 0) >= 1:
            systemic.append(
                "Combined automation and tooling gaps suggest need for DevSecOps transformation"
            )
        
        return systemic
    
    def _generate_summary(
        self,
        root_causes: List[RootCause],
        misconfigurations: List[Any]
    ) -> Dict[str, Any]:
        """Generate summary of root cause analysis"""
        by_category = {}
        for rc in root_causes:
            cat = rc.category.value
            if cat not in by_category:
                by_category[cat] = 0
            by_category[cat] += 1
        
        return {
            "total_root_causes": len(root_causes),
            "by_category": by_category,
            "average_confidence": sum(rc.confidence for rc in root_causes) / len(root_causes) if root_causes else 0,
            "misconfigurations_analyzed": len(misconfigurations),
            "primary_root_cause": root_causes[0].title if root_causes else "None identified",
        }
