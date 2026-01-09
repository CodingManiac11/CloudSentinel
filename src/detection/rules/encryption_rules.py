"""
Encryption and Data Protection Detection Rules

Detects missing or misconfigured encryption settings.
"""

from typing import Dict, Optional, Any

from .base_rule import BaseDetectionRule, RuleMetadata, register_rule
from ...models.cloud_resource import CloudResource, ResourceType, CloudProvider
from ...models.misconfiguration import Misconfiguration, Severity, MisconfigCategory


class UnencryptedStorageRule(BaseDetectionRule):
    """Detects storage resources without encryption"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="unencrypted-storage",
            name="Unencrypted Storage",
            description="Storage resource does not have encryption enabled",
            severity=Severity.HIGH,
            category=MisconfigCategory.ENCRYPTION,
            resource_types=[ResourceType.OBJECT_STORAGE, ResourceType.BLOCK_STORAGE],
            providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
            compliance_controls=["CIS-AWS-2.1.1", "SOC2-CC6.7", "HIPAA-164.312(a)(2)(iv)"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        if not resource.config.encryption_enabled:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Storage '{resource.name}' is not encrypted",
                description=(
                    f"The storage resource '{resource.name}' does not have encryption enabled. "
                    f"Data at rest should be encrypted to protect against unauthorized access "
                    f"in case of storage media theft or improper disposal. "
                    f"Data sensitivity: {resource.data_sensitivity.value.upper()}"
                ),
                evidence={
                    "encryption_enabled": False,
                    "data_sensitivity": resource.data_sensitivity.value,
                    "encryption_key_id": resource.config.encryption_key_id,
                }
            )
        
        return None


class UnencryptedDatabaseRule(BaseDetectionRule):
    """Detects databases without encryption at rest"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="unencrypted-database",
            name="Unencrypted Database",
            description="Database does not have encryption at rest enabled",
            severity=Severity.CRITICAL,
            category=MisconfigCategory.ENCRYPTION,
            resource_types=[ResourceType.DATABASE],
            providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
            compliance_controls=["CIS-AWS-2.3.1", "HIPAA-164.312(a)(2)(iv)", "PCI-DSS-3.4"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        is_encrypted = (
            resource.config.encryption_enabled or
            config.get("storage_encrypted", False)
        )
        
        if not is_encrypted:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Database '{resource.name}' is not encrypted at rest",
                description=(
                    f"The database '{resource.name}' does not have encryption at rest enabled. "
                    f"Database encryption protects data from unauthorized access and is required "
                    f"for compliance with most security frameworks."
                ),
                evidence={
                    "storage_encrypted": config.get("storage_encrypted"),
                    "engine": config.get("engine"),
                }
            )
        
        return None


class MissingTransportEncryptionRule(BaseDetectionRule):
    """Detects resources not enforcing transport encryption (HTTPS/TLS)"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="missing-transport-encryption",
            name="Missing Transport Encryption",
            description="Resource does not enforce HTTPS/TLS for connections",
            severity=Severity.MEDIUM,
            category=MisconfigCategory.ENCRYPTION,
            resource_types=[ResourceType.OBJECT_STORAGE, ResourceType.DATABASE, ResourceType.API_GATEWAY],
            providers=[CloudProvider.AWS, CloudProvider.AZURE],
            compliance_controls=["CIS-AWS-2.1.2", "SOC2-CC6.7", "PCI-DSS-4.1"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        # Check various indicators of missing transport encryption
        issues = []
        
        https_only = config.get("https_only", True)
        min_tls = config.get("minimum_tls_version", config.get("minimal_tls_version", "TLS1_2"))
        
        if not https_only:
            issues.append("HTTPS not enforced")
        
        if min_tls and min_tls in ["TLS1_0", "TLS1.0", "1.0"]:
            issues.append(f"Outdated TLS version: {min_tls}")
        
        if issues:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Resource '{resource.name}' has weak transport security",
                description=(
                    f"The resource '{resource.name}' has transport encryption issues: "
                    f"{'; '.join(issues)}. Data in transit should be protected with TLS 1.2 or higher."
                ),
                evidence={
                    "issues": issues,
                    "https_only": https_only,
                    "minimum_tls_version": min_tls,
                }
            )
        
        return None


class UnencryptedK8sSecretsRule(BaseDetectionRule):
    """Detects Kubernetes secrets not encrypted at rest"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="unencrypted-k8s-secrets",
            name="Unencrypted Kubernetes Secrets",
            description="Kubernetes secrets are not encrypted at rest in etcd",
            severity=Severity.HIGH,
            category=MisconfigCategory.ENCRYPTION,
            resource_types=[ResourceType.KUBERNETES_SECRET],
            providers=[CloudProvider.KUBERNETES],
            compliance_controls=["CIS-K8s-1.2.29", "NSA-CISA-K8s-Secrets"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        if not config.get("encrypted_at_rest", False):
            return self.create_misconfiguration(
                resource=resource,
                title=f"Kubernetes Secret '{resource.name}' is not encrypted at rest",
                description=(
                    f"The Kubernetes secret '{resource.name}' is not encrypted at rest in etcd. "
                    f"Secrets contain sensitive data like passwords and API keys. "
                    f"Enable encryption at rest for etcd to protect this data."
                ),
                evidence={
                    "secret_type": config.get("type"),
                    "data_keys": config.get("data_keys", []),
                    "encrypted_at_rest": False,
                }
            )
        
        return None


class MissingBackupEncryptionRule(BaseDetectionRule):
    """Detects databases without backup retention or encryption"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="missing-backup-config",
            name="Missing or Insecure Backup Configuration",
            description="Database backup retention is disabled or not configured securely",
            severity=Severity.MEDIUM,
            category=MisconfigCategory.DATA_PROTECTION,
            resource_types=[ResourceType.DATABASE],
            providers=[CloudProvider.AWS, CloudProvider.AZURE],
            compliance_controls=["CIS-AWS-2.3.2", "SOC2-A1.2"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        backup_retention = config.get("backup_retention", config.get("backup_retention_days", -1))
        
        if backup_retention == 0:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Database '{resource.name}' has backups disabled",
                description=(
                    f"The database '{resource.name}' has automated backups disabled "
                    f"(retention set to 0 days). This puts data at risk of loss. "
                    f"Enable automated backups with at least 7 days retention."
                ),
                evidence={
                    "backup_retention": backup_retention,
                    "deletion_protection": config.get("deletion_protection", False),
                }
            )
        
        return None


# Register rules
register_rule(UnencryptedStorageRule())
register_rule(UnencryptedDatabaseRule())
register_rule(MissingTransportEncryptionRule())
register_rule(UnencryptedK8sSecretsRule())
register_rule(MissingBackupEncryptionRule())
