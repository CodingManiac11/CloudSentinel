"""
Attack Graph Generator

Builds attack paths showing how misconfigurations can be chained together.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
import uuid

from ..models.cloud_resource import CloudResource, ResourceType, ExposureLevel, DataSensitivity
from ..models.misconfiguration import Misconfiguration, AttackPath, AttackPathNode
from ..discovery.resource_graph import ResourceGraphBuilder


@dataclass
class AttackScenario:
    """A complete attack scenario with multiple paths"""
    id: str
    name: str
    description: str
    paths: List[AttackPath]
    total_risk_score: float
    mitre_techniques: List[str]


class AttackGraphGenerator:
    """
    Generates attack graphs showing how misconfigurations can be exploited.
    
    This is a key differentiator - instead of just listing issues,
    we show HOW an attacker could chain them together to reach sensitive data.
    """
    
    # MITRE ATT&CK technique mapping
    TECHNIQUE_MAP = {
        "public_s3": ("T1530", "Data from Cloud Storage Object"),
        "public_db": ("T1190", "Exploit Public-Facing Application"),
        "overprivileged_role": ("T1078", "Valid Accounts"),
        "role_assumption": ("T1550", "Use Alternate Authentication Material"),
        "lateral_movement": ("T1021", "Remote Services"),
        "data_access": ("T1213", "Data from Information Repositories"),
        "privilege_escalation": ("T1548", "Abuse Elevation Control"),
    }
    
    def __init__(self, resource_graph: ResourceGraphBuilder):
        self.resource_graph = resource_graph
    
    def generate_attack_paths(
        self,
        misconfigurations: List[Misconfiguration],
        max_paths: int = 10
    ) -> List[AttackPath]:
        """
        Generate attack paths from entry points to sensitive targets.
        """
        # Build misconfiguration lookup
        misconfig_by_resource: Dict[str, List[Misconfiguration]] = {}
        for m in misconfigurations:
            if m.resource_id not in misconfig_by_resource:
                misconfig_by_resource[m.resource_id] = []
            misconfig_by_resource[m.resource_id].append(m)
        
        # Find raw paths from resource graph
        raw_paths = self.resource_graph.find_attack_paths(max_depth=5)
        
        # Convert to AttackPath objects with analysis
        attack_paths = []
        
        for raw_path in raw_paths[:max_paths]:
            if len(raw_path) < 2:
                continue
            
            attack_path = self._build_attack_path(raw_path, misconfig_by_resource)
            if attack_path:
                attack_paths.append(attack_path)
        
        # Sort by risk score
        attack_paths.sort(key=lambda p: p.total_risk_score, reverse=True)
        
        return attack_paths
    
    def generate_privilege_escalation_paths(
        self,
        misconfigurations: List[Misconfiguration]
    ) -> List[AttackPath]:
        """
        Find paths that lead to privilege escalation.
        """
        misconfig_by_resource: Dict[str, List[Misconfiguration]] = {}
        for m in misconfigurations:
            if m.resource_id not in misconfig_by_resource:
                misconfig_by_resource[m.resource_id] = []
            misconfig_by_resource[m.resource_id].append(m)
        
        raw_paths = self.resource_graph.get_privilege_escalation_paths()
        
        escalation_paths = []
        for raw_path in raw_paths[:5]:
            attack_path = self._build_attack_path(
                raw_path, 
                misconfig_by_resource,
                attack_type="privilege_escalation"
            )
            if attack_path:
                escalation_paths.append(attack_path)
        
        return escalation_paths
    
    def generate_attack_scenarios(
        self,
        misconfigurations: List[Misconfiguration]
    ) -> List[AttackScenario]:
        """
        Generate complete attack scenarios combining related paths.
        """
        all_paths = self.generate_attack_paths(misconfigurations)
        escalation_paths = self.generate_privilege_escalation_paths(misconfigurations)
        
        scenarios = []
        
        # Scenario 1: Data Breach via Public Exposure
        public_entry_paths = [p for p in all_paths if p.attack_type == "data_exfiltration"]
        if public_entry_paths:
            scenarios.append(AttackScenario(
                id=f"scenario-{uuid.uuid4().hex[:8]}",
                name="Data Breach via Public Cloud Resources",
                description=(
                    "An attacker discovers publicly accessible cloud resources and uses "
                    "misconfigurations to access sensitive data. This is a common attack "
                    "pattern that has led to major data breaches."
                ),
                paths=public_entry_paths[:3],
                total_risk_score=max(p.total_risk_score for p in public_entry_paths),
                mitre_techniques=["T1530", "T1190", "T1213"]
            ))
        
        # Scenario 2: Privilege Escalation
        if escalation_paths:
            scenarios.append(AttackScenario(
                id=f"scenario-{uuid.uuid4().hex[:8]}",
                name="Privilege Escalation Attack",
                description=(
                    "An attacker with initial access uses over-permissive IAM configurations "
                    "to escalate privileges and gain administrative control. This allows "
                    "access to all resources in the environment."
                ),
                paths=escalation_paths[:3],
                total_risk_score=max(p.total_risk_score for p in escalation_paths),
                mitre_techniques=["T1078", "T1548", "T1550"]
            ))
        
        # Scenario 3: Lateral Movement
        lateral_paths = [p for p in all_paths if len(p.nodes) >= 3]
        if lateral_paths:
            scenarios.append(AttackScenario(
                id=f"scenario-{uuid.uuid4().hex[:8]}",
                name="Lateral Movement to Critical Assets",
                description=(
                    "An attacker moves laterally through the infrastructure, hopping between "
                    "connected resources to reach high-value targets. Network segmentation "
                    "issues and trust relationships enable this attack."
                ),
                paths=lateral_paths[:3],
                total_risk_score=max(p.total_risk_score for p in lateral_paths),
                mitre_techniques=["T1021", "T1570", "T1550"]
            ))
        
        return scenarios
    
    def _build_attack_path(
        self,
        path_ids: List[str],
        misconfig_lookup: Dict[str, List[Misconfiguration]],
        attack_type: str = None
    ) -> Optional[AttackPath]:
        """Build a detailed AttackPath from a list of resource IDs"""
        if len(path_ids) < 2:
            return None
        
        nodes = []
        misconfiguration_ids = []
        total_risk = 0.0
        techniques = []
        
        for i, resource_id in enumerate(path_ids):
            resource = self.resource_graph.get_resource(resource_id)
            if not resource:
                continue
            
            # Get misconfigurations for this resource
            misconfigs = misconfig_lookup.get(resource_id, [])
            
            # Determine action at this step
            if i == 0:
                action = self._get_entry_action(resource)
            else:
                action = self._get_transition_action(
                    self.resource_graph.get_resource(path_ids[i-1]),
                    resource
                )
            
            # Determine access gained
            access_gained = self._determine_access_gained(resource, misconfigs)
            
            node = AttackPathNode(
                resource_id=resource_id,
                resource_name=resource.name,
                resource_type=resource.resource_type.value,
                misconfiguration_id=misconfigs[0].id if misconfigs else None,
                action=action,
                access_gained=access_gained
            )
            nodes.append(node)
            
            # Track misconfigurations
            for m in misconfigs:
                misconfiguration_ids.append(m.id)
                if m.risk_score:
                    total_risk = max(total_risk, m.risk_score.score)
        
        if not nodes:
            return None
        
        # Determine attack type if not specified
        if not attack_type:
            attack_type = self._determine_attack_type(nodes)
        
        # Get target description
        target_resource = self.resource_graph.get_resource(path_ids[-1])
        target = self._get_target_description(target_resource) if target_resource else "Unknown target"
        
        return AttackPath(
            id=f"path-{uuid.uuid4().hex[:8]}",
            name=self._generate_path_name(nodes, attack_type),
            description=self._generate_path_description(nodes, target),
            nodes=nodes,
            entry_point=path_ids[0],
            target=target,
            total_risk_score=total_risk,
            exploitability=self._determine_exploitability(misconfiguration_ids, misconfig_lookup),
            impact=self._determine_impact(target_resource) if target_resource else "unknown",
            misconfiguration_ids=misconfiguration_ids,
            attack_type=attack_type,
            techniques=techniques
        )
    
    def _get_entry_action(self, resource: CloudResource) -> str:
        """Get the initial entry action for an attack path"""
        if resource.config.public_access:
            return "Access publicly exposed resource"
        if resource.exposure_level == ExposureLevel.INTERNET:
            return "Connect to internet-facing service"
        return "Gain initial access"
    
    def _get_transition_action(self, from_resource: CloudResource, to_resource: CloudResource) -> str:
        """Get the action to move between resources"""
        from_type = from_resource.resource_type
        to_type = to_resource.resource_type
        
        if to_type in [ResourceType.IAM_ROLE, ResourceType.SERVICE_ACCOUNT]:
            return "Assume role/service account"
        if to_type == ResourceType.DATABASE:
            return "Connect to database"
        if to_type in [ResourceType.OBJECT_STORAGE]:
            return "Access storage bucket"
        if from_type == ResourceType.IAM_ROLE:
            return "Use escalated permissions"
        
        return "Pivot to connected resource"
    
    def _determine_access_gained(self, resource: CloudResource, misconfigs: List[Misconfiguration]) -> str:
        """Determine what access is gained at this step"""
        if resource.resource_type == ResourceType.DATABASE:
            return "Database read/write access"
        if resource.resource_type == ResourceType.OBJECT_STORAGE:
            return "Storage data access"
        if resource.resource_type in [ResourceType.IAM_ROLE, ResourceType.SERVICE_ACCOUNT]:
            return "Elevated permissions"
        if resource.resource_type == ResourceType.KEY_VAULT:
            return "Secrets and credentials"
        if resource.resource_type == ResourceType.COMPUTE_INSTANCE:
            return "Command execution"
        
        return "Resource access"
    
    def _determine_attack_type(self, nodes: List[AttackPathNode]) -> str:
        """Determine the overall attack type"""
        has_iam = any("iam" in n.resource_type.lower() or n.access_gained == "Elevated permissions" for n in nodes)
        has_data = any("database" in n.resource_type.lower() or "storage" in n.resource_type.lower() for n in nodes)
        
        if has_iam and len(nodes) > 2:
            return "privilege_escalation"
        if has_data:
            return "data_exfiltration"
        return "lateral_movement"
    
    def _get_target_description(self, resource: CloudResource) -> str:
        """Get description of the attack target"""
        if resource.data_sensitivity == DataSensitivity.RESTRICTED:
            return "Access to restricted/PII data"
        if resource.resource_type == ResourceType.DATABASE:
            return "Database containing customer data"
        if resource.resource_type == ResourceType.KEY_VAULT:
            return "Secrets and API keys"
        if resource.resource_type == ResourceType.IAM_ROLE:
            return "Administrative privileges"
        return f"Access to {resource.name}"
    
    def _generate_path_name(self, nodes: List[AttackPathNode], attack_type: str) -> str:
        """Generate a descriptive name for the attack path"""
        if attack_type == "privilege_escalation":
            return f"Privilege Escalation via {nodes[0].resource_name}"
        if attack_type == "data_exfiltration":
            return f"Data Access: {nodes[0].resource_name} → {nodes[-1].resource_name}"
        return f"Attack Path: {nodes[0].resource_name} → {nodes[-1].resource_name}"
    
    def _generate_path_description(self, nodes: List[AttackPathNode], target: str) -> str:
        """Generate narrative description of the attack path"""
        parts = []
        for i, node in enumerate(nodes):
            if i == 0:
                parts.append(f"Attacker gains access to {node.resource_name}")
            else:
                parts.append(f"then {node.action.lower()}")
        
        parts.append(f"to achieve: {target}")
        return " ".join(parts)
    
    def _determine_exploitability(
        self, 
        misconfig_ids: List[str], 
        lookup: Dict[str, List[Misconfiguration]]
    ) -> str:
        """Determine how easy it is to exploit this path"""
        # Flatten all misconfigs
        all_misconfigs = []
        for misconfigs in lookup.values():
            all_misconfigs.extend(misconfigs)
        
        # Filter to just those in this path
        path_misconfigs = [m for m in all_misconfigs if m.id in misconfig_ids]
        
        if not path_misconfigs:
            return "medium"
        
        # Check for easy-to-exploit issues
        from ..models.misconfiguration import MisconfigCategory, Severity
        
        has_public = any(m.category == MisconfigCategory.PUBLIC_EXPOSURE for m in path_misconfigs)
        has_critical = any(m.severity == Severity.CRITICAL for m in path_misconfigs)
        
        if has_public and has_critical:
            return "high"
        if has_public or has_critical:
            return "medium"
        return "low"
    
    def _determine_impact(self, resource: CloudResource) -> str:
        """Determine impact level if target is compromised"""
        if resource.data_sensitivity == DataSensitivity.RESTRICTED:
            return "critical"
        if resource.data_sensitivity == DataSensitivity.CONFIDENTIAL:
            return "high"
        if resource.criticality_score >= 0.8:
            return "high"
        if resource.criticality_score >= 0.5:
            return "medium"
        return "low"
