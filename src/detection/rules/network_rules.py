"""
Network Security Detection Rules

Detects insecure network configurations and security group rules.
"""

from typing import Dict, Optional, Any, List

from .base_rule import BaseDetectionRule, RuleMetadata, register_rule
from ...models.cloud_resource import CloudResource, ResourceType, CloudProvider
from ...models.misconfiguration import Misconfiguration, Severity, MisconfigCategory


class OpenSecurityGroupRule(BaseDetectionRule):
    """Detects security groups with overly permissive inbound rules"""
    
    SENSITIVE_PORTS = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
        445: "SMB",
        135: "RPC",
    }
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="open-security-group",
            name="Overly Permissive Security Group",
            description="Security group allows unrestricted access from the internet",
            severity=Severity.HIGH,
            category=MisconfigCategory.NETWORK_SECURITY,
            resource_types=[ResourceType.SECURITY_GROUP],
            providers=[CloudProvider.AWS, CloudProvider.AZURE],
            compliance_controls=["CIS-AWS-5.2", "CIS-Azure-6.1", "PCI-DSS-1.3"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        inbound_rules = config.get("inbound_rules", []) or config.get("security_rules", [])
        
        open_ports = []
        
        for rule in inbound_rules:
            source = rule.get("source", rule.get("source_address_prefix", ""))
            port = rule.get("port", rule.get("destination_port", ""))
            
            # Check if rule allows from anywhere
            is_open = source in ["0.0.0.0/0", "*", "::/0"]
            
            if is_open and rule.get("access", "Allow") != "Deny":
                try:
                    port_num = int(port) if port != "all" else -1
                except (ValueError, TypeError):
                    port_num = -1
                
                port_name = self.SENSITIVE_PORTS.get(port_num, f"Port {port}")
                
                if port_num in self.SENSITIVE_PORTS or port_num == -1:
                    open_ports.append({
                        "port": port,
                        "name": port_name,
                        "source": source,
                    })
        
        if open_ports:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Security Group '{resource.name}' allows unrestricted internet access",
                description=(
                    f"The security group '{resource.name}' allows unrestricted access from "
                    f"the internet (0.0.0.0/0) to sensitive ports: "
                    f"{', '.join([p['name'] for p in open_ports])}. "
                    f"This exposes services to potential attacks from anywhere."
                ),
                evidence={
                    "open_ports": open_ports,
                    "recommendation": "Restrict access to specific IP ranges or use a bastion host",
                }
            )
        
        return None


class UnrestrictedOutboundRule(BaseDetectionRule):
    """Detects security groups with unrestricted outbound access"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="unrestricted-outbound",
            name="Unrestricted Outbound Access",
            description="Security group allows all outbound traffic",
            severity=Severity.LOW,
            category=MisconfigCategory.NETWORK_SECURITY,
            resource_types=[ResourceType.SECURITY_GROUP],
            providers=[CloudProvider.AWS, CloudProvider.AZURE],
            compliance_controls=["CIS-AWS-5.4"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        outbound_rules = config.get("outbound_rules", [])
        
        for rule in outbound_rules:
            protocol = rule.get("protocol", "")
            destination = rule.get("destination", "")
            port = rule.get("port", "")
            
            if destination == "0.0.0.0/0" and (port == "all" or protocol == "-1"):
                return self.create_misconfiguration(
                    resource=resource,
                    title=f"Security Group '{resource.name}' allows unrestricted outbound traffic",
                    description=(
                        f"The security group '{resource.name}' allows all outbound traffic to "
                        f"any destination. While this is common, it could allow data exfiltration "
                        f"if a resource is compromised. Consider restricting outbound rules."
                    ),
                    evidence={
                        "outbound_rules": outbound_rules,
                    }
                )
        
        return None


class MissingNetworkPolicyRule(BaseDetectionRule):
    """Detects Kubernetes namespaces without network policies"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="k8s-no-network-policy",
            name="Missing Kubernetes Network Policy",
            description="Kubernetes namespace has no network policies defined",
            severity=Severity.MEDIUM,
            category=MisconfigCategory.NETWORK_SECURITY,
            resource_types=[ResourceType.KUBERNETES_NAMESPACE],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-5.3.2", "NSA-CISA-K8s-NP"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        network_policies = config.get("network_policies", [])
        
        if not network_policies:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Namespace '{resource.name}' has no network policies",
                description=(
                    f"The Kubernetes namespace '{resource.name}' has no network policies defined. "
                    f"Without network policies, all pods can communicate with each other, "
                    f"allowing lateral movement if a pod is compromised."
                ),
                evidence={
                    "namespace": resource.name,
                    "network_policies_count": 0,
                }
            )
        
        return None


class WideOpenFirewallRule(BaseDetectionRule):
    """Detects database firewall rules that allow all IPs"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="wide-open-firewall",
            name="Database Firewall Allows All IPs",
            description="Database firewall rule allows connections from any IP address",
            severity=Severity.CRITICAL,
            category=MisconfigCategory.NETWORK_SECURITY,
            resource_types=[ResourceType.DATABASE],
            providers=[CloudProvider.AZURE],
            compliance_controls=["CIS-Azure-4.1.2", "SOC2-CC6.6"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        firewall_rules = config.get("firewall_rules", [])
        
        for rule in firewall_rules:
            start_ip = rule.get("start_ip", "")
            end_ip = rule.get("end_ip", "")
            
            # Check for Allow All pattern
            if start_ip == "0.0.0.0" and end_ip in ["255.255.255.255", "0.0.0.0"]:
                return self.create_misconfiguration(
                    resource=resource,
                    title=f"Database '{resource.name}' firewall allows all IP addresses",
                    description=(
                        f"The database '{resource.name}' has a firewall rule that allows "
                        f"connections from any IP address (0.0.0.0/0). This effectively "
                        f"disables the firewall and exposes the database to the entire internet."
                    ),
                    evidence={
                        "firewall_rule": rule,
                        "start_ip": start_ip,
                        "end_ip": end_ip,
                    }
                )
        
        return None


# Register rules
register_rule(OpenSecurityGroupRule())
register_rule(UnrestrictedOutboundRule())
register_rule(MissingNetworkPolicyRule())
register_rule(WideOpenFirewallRule())
