"""
Public Exposure Detection Rules

Detects resources that are unintentionally publicly accessible.
"""

from typing import Dict, Optional, Any

from .base_rule import BaseDetectionRule, RuleMetadata, register_rule
from ...models.cloud_resource import CloudResource, ResourceType, CloudProvider, ExposureLevel
from ...models.misconfiguration import Misconfiguration, Severity, MisconfigCategory


class PublicS3BucketRule(BaseDetectionRule):
    """Detects S3 buckets with public access enabled"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="public-s3-bucket",
            name="Public S3 Bucket",
            description="S3 bucket allows public access, potentially exposing sensitive data",
            severity=Severity.CRITICAL,
            category=MisconfigCategory.PUBLIC_EXPOSURE,
            resource_types=[ResourceType.OBJECT_STORAGE],
            providers=[CloudProvider.AWS],
            compliance_controls=["CIS-AWS-2.1.5", "SOC2-CC6.7", "PCI-DSS-7.1"],
            cis_benchmark="CIS AWS Foundations Benchmark v1.4.0 - 2.1.5",
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        # Check public access block settings
        public_access_block = config.get("public_access_block", {})
        is_public = (
            not public_access_block.get("BlockPublicAcls", True) or
            not public_access_block.get("BlockPublicPolicy", True) or
            resource.config.public_access
        )
        
        # Check bucket policy for public access
        bucket_policy = config.get("bucket_policy", {})
        has_public_policy = False
        for statement in bucket_policy.get("Statement", []):
            if statement.get("Principal") == "*" and statement.get("Effect") == "Allow":
                has_public_policy = True
                break
        
        if is_public or has_public_policy:
            return self.create_misconfiguration(
                resource=resource,
                title=f"S3 Bucket '{resource.name}' is publicly accessible",
                description=(
                    f"The S3 bucket '{resource.name}' has public access enabled. "
                    f"This could expose sensitive data to the internet. "
                    f"Data sensitivity: {resource.data_sensitivity.value.upper()}"
                ),
                evidence={
                    "public_access_block": public_access_block,
                    "has_public_policy": has_public_policy,
                    "data_sensitivity": resource.data_sensitivity.value,
                }
            )
        
        return None


class PublicDatabaseRule(BaseDetectionRule):
    """Detects databases that are publicly accessible"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="public-database",
            name="Publicly Accessible Database",
            description="Database is accessible from the public internet",
            severity=Severity.CRITICAL,
            category=MisconfigCategory.PUBLIC_EXPOSURE,
            resource_types=[ResourceType.DATABASE],
            providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
            compliance_controls=["CIS-AWS-2.3.1", "SOC2-CC6.6", "HIPAA-164.312(e)"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        is_public = (
            config.get("publicly_accessible", False) or
            config.get("public_network_access") == "Enabled" or
            resource.exposure_level == ExposureLevel.INTERNET
        )
        
        if is_public:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Database '{resource.name}' is publicly accessible",
                description=(
                    f"The database '{resource.name}' is accessible from the public internet. "
                    f"This is a critical security risk as it exposes your data layer to potential attacks. "
                    f"Database ports like 3306 (MySQL), 5432 (PostgreSQL), or 1433 (SQL Server) "
                    f"should never be exposed to the internet."
                ),
                evidence={
                    "publicly_accessible": config.get("publicly_accessible"),
                    "public_network_access": config.get("public_network_access"),
                    "ports": resource.config.ports_open,
                }
            )
        
        return None


class PublicStorageAccountRule(BaseDetectionRule):
    """Detects Azure Storage Accounts with public blob access"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="public-storage-account",
            name="Public Azure Storage Account",
            description="Azure Storage Account allows public blob access",
            severity=Severity.HIGH,
            category=MisconfigCategory.PUBLIC_EXPOSURE,
            resource_types=[ResourceType.OBJECT_STORAGE],
            providers=[CloudProvider.AZURE],
            compliance_controls=["CIS-Azure-3.7", "SOC2-CC6.7"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        if config.get("allow_blob_public_access", False):
            return self.create_misconfiguration(
                resource=resource,
                title=f"Storage Account '{resource.name}' allows public blob access",
                description=(
                    f"The Azure Storage Account '{resource.name}' has public blob access enabled. "
                    f"This could allow anonymous access to stored data."
                ),
                evidence={
                    "allow_blob_public_access": True,
                    "https_only": config.get("https_only", True),
                    "minimum_tls_version": config.get("minimum_tls_version"),
                }
            )
        
        return None


class InternetExposedComputeRule(BaseDetectionRule):
    """Detects compute instances directly exposed to the internet"""
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="internet-exposed-compute",
            name="Internet-Exposed Compute Instance",
            description="Compute instance has a public IP and sensitive ports exposed",
            severity=Severity.HIGH,
            category=MisconfigCategory.PUBLIC_EXPOSURE,
            resource_types=[ResourceType.COMPUTE_INSTANCE],
            providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
            compliance_controls=["CIS-AWS-5.2", "NIST-SC-7"],
        )
    
    def evaluate(self, resource: CloudResource, context: Dict[str, Any] = None) -> Optional[Misconfiguration]:
        if not self.applies_to(resource):
            return None
        
        config = resource.config.raw_config
        
        has_public_ip = config.get("public_ip") or config.get("public_ip_address")
        sensitive_ports = [22, 3389, 3306, 5432, 27017, 6379, 9200]
        exposed_sensitive_ports = [p for p in resource.config.ports_open if p in sensitive_ports]
        
        if has_public_ip and exposed_sensitive_ports:
            return self.create_misconfiguration(
                resource=resource,
                title=f"Instance '{resource.name}' exposes sensitive ports to the internet",
                description=(
                    f"The compute instance '{resource.name}' has a public IP address "
                    f"and exposes sensitive ports: {exposed_sensitive_ports}. "
                    f"This significantly increases the attack surface."
                ),
                evidence={
                    "public_ip": has_public_ip,
                    "exposed_sensitive_ports": exposed_sensitive_ports,
                    "all_open_ports": resource.config.ports_open,
                }
            )
        
        return None


# Register rules
register_rule(PublicS3BucketRule())
register_rule(PublicDatabaseRule())
register_rule(PublicStorageAccountRule())
register_rule(InternetExposedComputeRule())
