"""
Kubernetes Security Detection Rules

Detects security misconfigurations in Kubernetes workloads.
"""

from typing import Dict, Optional, Any, List

from .base_rule import BaseDetectionRule, RuleMetadata, register_rule
from ...models.cloud_resource import CloudResource, ResourceType, CloudProvider
from ...models.misconfiguration import Misconfiguration, Severity, MisconfigCategory


class PrivilegedContainerRule(BaseDetectionRule):
    """Detects containers running in privileged mode"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="k8s-privileged-container",
            name="Privileged Container",
            description="Container is running in privileged mode, granting full host access",
            severity=Severity.CRITICAL,
            category=MisconfigCategory.KUBERNETES_SECURITY,
            resource_types=[ResourceType.KUBERNETES_DEPLOYMENT, ResourceType.KUBERNETES_POD],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-5.2.1", "NSA-CISA-K8s-Pods"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        containers = config.get("containers", [])
        
        privileged_containers = []
        
        for container in containers:
            sec_context = container.get("security_context", {})
            if sec_context.get("privileged", False):
                privileged_containers.append(container.get("name", "unknown"))
        
        if privileged_containers:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Workload '{resource.name}' has privileged containers",
                description=(
                    f"The Kubernetes workload '{resource.name}' has containers running in privileged mode: "
                    f"{', '.join(privileged_containers)}. Privileged containers have full access to the "
                    f"host system and can easily escape the container boundary."
                ),
                evidence={
                    "privileged_containers": privileged_containers,
                    "recommendation": "Remove privileged: true from security context",
                }
            )
        
        return None


class RunAsRootRule(BaseDetectionRule):
    """Detects containers running as root"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="k8s-run-as-root",
            name="Container Running as Root",
            description="Container is configured to run as root user",
            severity=Severity.HIGH,
            category=MisconfigCategory.KUBERNETES_SECURITY,
            resource_types=[ResourceType.KUBERNETES_DEPLOYMENT, ResourceType.KUBERNETES_POD],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-5.2.6", "NSA-CISA-K8s-Pods"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        containers = config.get("containers", [])
        
        root_containers = []
        
        for container in containers:
            sec_context = container.get("security_context", {})
            if sec_context.get("run_as_root", False) or sec_context.get("runAsUser") == 0:
                root_containers.append(container.get("name", "unknown"))
        
        if root_containers:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Workload '{resource.name}' runs as root",
                description=(
                    f"The Kubernetes workload '{resource.name}' has containers running as root: "
                    f"{', '.join(root_containers)}. Running as root increases the impact of "
                    f"container breakout vulnerabilities."
                ),
                evidence={
                    "root_containers": root_containers,
                    "recommendation": "Use runAsNonRoot: true and specify runAsUser",
                }
            )
        
        return None


class HostNetworkAccessRule(BaseDetectionRule):
    """Detects pods using host network namespace"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="k8s-host-network",
            name="Pod Using Host Network",
            description="Pod is using the host's network namespace",
            severity=Severity.HIGH,
            category=MisconfigCategory.KUBERNETES_SECURITY,
            resource_types=[ResourceType.KUBERNETES_POD],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-5.2.4"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        issues = []
        
        if config.get("host_network", False):
            issues.append("hostNetwork: true")
        if config.get("host_pid", False):
            issues.append("hostPID: true")
        if config.get("host_ipc", False):
            issues.append("hostIPC: true")
        
        if issues:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Pod '{resource.name}' uses host namespaces",
                description=(
                    f"The Kubernetes pod '{resource.name}' has access to host namespaces: "
                    f"{', '.join(issues)}. This breaks container isolation and allows "
                    f"the pod to interact with the host system."
                ),
                evidence={
                    "host_namespace_access": issues,
                    "host_network": config.get("host_network"),
                    "host_pid": config.get("host_pid"),
                }
            )
        
        return None


class LatestImageTagRule(BaseDetectionRule):
    """Detects containers using the 'latest' image tag"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="k8s-latest-tag",
            name="Container Using Latest Tag",
            description="Container image uses 'latest' tag which is not reproducible",
            severity=Severity.MEDIUM,
            category=MisconfigCategory.KUBERNETES_SECURITY,
            resource_types=[ResourceType.KUBERNETES_DEPLOYMENT],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-5.4.1"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        containers = config.get("containers", [])
        
        latest_images = []
        
        for container in containers:
            image = container.get("image", "")
            if image.endswith(":latest") or ":" not in image:
                latest_images.append(image)
        
        if latest_images:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Deployment '{resource.name}' uses 'latest' image tag",
                description=(
                    f"The Kubernetes deployment '{resource.name}' uses 'latest' or untagged images: "
                    f"{', '.join(latest_images)}. This makes deployments non-reproducible and "
                    f"could lead to unexpected changes when pods restart."
                ),
                evidence={
                    "images_with_latest": latest_images,
                    "recommendation": "Use specific version tags for images",
                }
            )
        
        return None


class MissingResourceLimitsRule(BaseDetectionRule):
    """Detects containers without resource limits"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="k8s-no-resource-limits",
            name="Missing Resource Limits",
            description="Container does not have CPU/memory limits defined",
            severity=Severity.MEDIUM,
            category=MisconfigCategory.KUBERNETES_SECURITY,
            resource_types=[ResourceType.KUBERNETES_DEPLOYMENT],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-5.4.2"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        containers = config.get("containers", [])
        
        containers_without_limits = []
        
        for container in containers:
            resources = container.get("resources", {})
            limits = resources.get("limits")
            
            if not limits:
                containers_without_limits.append(container.get("name", "unknown"))
        
        if containers_without_limits:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Deployment '{resource.name}' has no resource limits",
                description=(
                    f"The Kubernetes deployment '{resource.name}' has containers without resource limits: "
                    f"{', '.join(containers_without_limits)}. Without limits, a container could consume "
                    f"all node resources, causing denial of service."
                ),
                evidence={
                    "containers_without_limits": containers_without_limits,
                    "recommendation": "Define CPU and memory limits for all containers",
                }
            )
        
        return None


class AllowPrivilegeEscalationRule(BaseDetectionRule):
    """Detects containers that allow privilege escalation"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="k8s-privilege-escalation",
            name="Privilege Escalation Allowed",
            description="Container allows privilege escalation via setuid binaries",
            severity=Severity.HIGH,
            category=MisconfigCategory.KUBERNETES_SECURITY,
            resource_types=[ResourceType.KUBERNETES_DEPLOYMENT],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-5.2.5", "NSA-CISA-K8s-Pods"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        containers = config.get("containers", [])
        
        escalation_allowed = []
        
        for container in containers:
            sec_context = container.get("security_context", {})
            if sec_context.get("allow_privilege_escalation", True):  # Default is true!
                escalation_allowed.append(container.get("name", "unknown"))
        
        if escalation_allowed:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Deployment '{resource.name}' allows privilege escalation",
                description=(
                    f"The Kubernetes deployment '{resource.name}' has containers that allow "
                    f"privilege escalation: {', '.join(escalation_allowed)}. This means setuid/setgid "
                    f"binaries can be used to gain higher privileges."
                ),
                evidence={
                    "containers_with_escalation": escalation_allowed,
                    "recommendation": "Set allowPrivilegeEscalation: false in security context",
                }
            )
        
        return None


# Register rules
register_rule(PrivilegedContainerRule())
register_rule(RunAsRootRule())
register_rule(HostNetworkAccessRule())
register_rule(LatestImageTagRule())
register_rule(MissingResourceLimitsRule())
register_rule(AllowPrivilegeEscalationRule())
