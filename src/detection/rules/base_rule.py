"""
Base Detection Rule Interface

Provides the foundation for creating modular detection rules.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ...models.cloud_resource import CloudResource, ResourceType, CloudProvider
from ...models.misconfiguration import Misconfiguration, Severity, MisconfigCategory


@dataclass
class RuleMetadata:
    """Metadata about a detection rule"""
    id: str
    name: str
    description: str
    severity: Severity
    category: MisconfigCategory
    
    # Rule characteristics
    resource_types: List[ResourceType]
    providers: List[CloudProvider]
    
    # Compliance mapping
    compliance_controls: List[str] = None
    
    # References
    remediation_url: Optional[str] = None
    cis_benchmark: Optional[str] = None


class BaseDetectionRule(ABC):
    """
    Abstract base class for all detection rules.
    Each rule checks for a specific type of misconfiguration.
    """
    
    @property
    @abstractmethod
    def metadata(self) -> RuleMetadata:
        """Return rule metadata"""
        pass
    
    @abstractmethod
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        """
        Evaluate the rule against a resource.
        
        Args:
            resource: The cloud resource to check
            context: Additional context (related resources, etc.)
            
        Returns:
            Misconfiguration if found, None otherwise
        """
        pass
    
    def applies_to(self, resource: CloudResource) -> bool:
        """Check if this rule applies to the given resource"""
        if self.metadata.resource_types and resource.resource_type not in self.metadata.resource_types:
            return False
        if self.metadata.providers and resource.provider not in self.metadata.providers:
            return False
        return True
    
    def create_misconfiguration(
        self,
        resource: CloudResource,
        title: str,
        description: str,
        evidence: Dict[str, Any] = None
    ) -> Misconfiguration:
        """Helper to create a misconfiguration finding"""
        import uuid
        
        return Misconfiguration(
            id=f"misc-{uuid.uuid4().hex[:8]}",
            title=title,
            description=description,
            severity=self.metadata.severity,
            category=self.metadata.category,
            resource_id=resource.id,
            resource_name=resource.name,
            resource_type=resource.resource_type.value,
            provider=resource.provider.value,
            rule_id=self.metadata.id,
            rule_name=self.metadata.name,
            evidence=evidence or {},
            compliance_violations=self.metadata.compliance_controls or [],
        )


class RuleRegistry:
    """
    Registry of all detection rules.
    Manages rule lifecycle and execution.
    """
    
    def __init__(self):
        self.rules: Dict[str, BaseDetectionRule] = {}
    
    def register(self, rule: BaseDetectionRule) -> None:
        """Register a detection rule"""
        self.rules[rule.metadata.id] = rule
    
    def unregister(self, rule_id: str) -> None:
        """Remove a rule from the registry"""
        if rule_id in self.rules:
            del self.rules[rule_id]
    
    def get_rule(self, rule_id: str) -> Optional[BaseDetectionRule]:
        """Get a specific rule by ID"""
        return self.rules.get(rule_id)
    
    def get_rules_for_resource(self, resource: CloudResource) -> List[BaseDetectionRule]:
        """Get all rules applicable to a resource"""
        return [rule for rule in self.rules.values() if rule.applies_to(resource)]
    
    def get_rules_by_category(self, category: MisconfigCategory) -> List[BaseDetectionRule]:
        """Get all rules in a category"""
        return [rule for rule in self.rules.values() if rule.metadata.category == category]
    
    def get_rules_by_severity(self, severity: Severity) -> List[BaseDetectionRule]:
        """Get all rules of a severity"""
        return [rule for rule in self.rules.values() if rule.metadata.severity == severity]
    
    def get_all_rules(self) -> List[BaseDetectionRule]:
        """Get all registered rules"""
        return list(self.rules.values())
    
    def evaluate_resource(
        self, 
        resource: CloudResource, 
        context: Dict[str, Any] = None
    ) -> List[Misconfiguration]:
        """Run all applicable rules against a resource"""
        misconfigurations = []
        
        for rule in self.get_rules_for_resource(resource):
            try:
                result = rule.evaluate(resource, context)
                if result:
                    misconfigurations.append(result)
            except Exception as e:
                # Log error but continue with other rules
                print(f"Error evaluating rule {rule.metadata.id}: {e}")
        
        return misconfigurations


# Global rule registry
_global_registry = RuleRegistry()


def get_rule_registry() -> RuleRegistry:
    """Get the global rule registry"""
    return _global_registry


def register_rule(rule: BaseDetectionRule) -> None:
    """Register a rule in the global registry"""
    _global_registry.register(rule)
