"""
Azure Cloud Provider Implementation

Discovers and enumerates Azure resources for security analysis.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime

from .base_provider import BaseCloudProvider
from ..models.cloud_resource import (
    CloudResource, CloudProvider, ResourceType,
    ResourceConfiguration, ResourceMetadata,
    DataSensitivity, ExposureLevel
)


class AzureProvider(BaseCloudProvider):
    """
    Azure resource discovery implementation.
    In production, this would use azure-sdk-for-python.
    For demo, uses simulated infrastructure.
    """
    
    @property
    def provider_name(self) -> CloudProvider:
        return CloudProvider.AZURE
    
    async def connect(self) -> bool:
        """Simulate Azure connection"""
        self._initialized = True
        return True
    
    async def discover_resources(self, resource_types: Optional[List[ResourceType]] = None) -> List[CloudResource]:
        """Discover Azure resources"""
        resources = []
        
        resources.extend(self._discover_storage_accounts())
        resources.extend(self._discover_virtual_machines())
        resources.extend(self._discover_sql_databases())
        resources.extend(self._discover_key_vaults())
        resources.extend(self._discover_network_security_groups())
        
        if resource_types:
            resources = [r for r in resources if r.resource_type in resource_types]
        
        return resources
    
    async def get_resource_config(self, resource_id: str) -> Dict[str, Any]:
        """Get resource configuration"""
        resource = self.resources.get(resource_id)
        if resource:
            return resource.config.raw_config
        return {}
    
    async def get_resource_relationships(self, resource_id: str) -> List[tuple]:
        """Get resource relationships"""
        resource = self.resources.get(resource_id)
        if resource:
            return [(target, "connected") for target in resource.connected_to]
        return []
    
    def _discover_storage_accounts(self) -> List[CloudResource]:
        """Simulate Azure Storage Account discovery"""
        storage_accounts = []
        
        # Public blob storage (misconfigured)
        storage_accounts.append(CloudResource(
            id="azure-storage-publicdata",
            name="acmepublicdatastorage",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.OBJECT_STORAGE,
            arn="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/acmepublicdatastorage",
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            exposure_level=ExposureLevel.INTERNET,
            criticality_score=0.85,
            config=ResourceConfiguration(
                raw_config={
                    "allow_blob_public_access": True,  # Misconfigured!
                    "minimum_tls_version": "TLS1_0",  # Outdated!
                    "https_only": False,  # Misconfigured!
                    "network_rules": {
                        "default_action": "Allow",
                        "ip_rules": [],
                        "virtual_network_rules": []
                    }
                },
                encryption_enabled=True,
                public_access=True,
                logging_enabled=False,
            ),
            metadata=ResourceMetadata(
                region="eastus",
                project_id="sub-123",
                tags={"Environment": "production"},
            ),
        ))
        
        return storage_accounts
    
    def _discover_virtual_machines(self) -> List[CloudResource]:
        """Simulate Azure VM discovery"""
        vms = []
        
        # VM with unmanaged disk
        vms.append(CloudResource(
            id="azure-vm-webserver",
            name="prod-webserver-01",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.COMPUTE_INSTANCE,
            arn="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/prod-webserver-01",
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            exposure_level=ExposureLevel.INTERNET,
            criticality_score=0.75,
            config=ResourceConfiguration(
                raw_config={
                    "os_type": "Linux",
                    "os_disk_encryption": False,  # Misconfigured!
                    "public_ip_address": "20.123.45.67",
                    "boot_diagnostics": False,
                },
                encryption_enabled=False,
                public_access=True,
                ports_open=[22, 80, 443],
            ),
            metadata=ResourceMetadata(
                region="eastus",
                project_id="sub-123",
                tags={"Environment": "production", "Application": "web"},
            ),
            connected_to=["azure-nsg-webserver", "azure-sql-prod"],
        ))
        
        return vms
    
    def _discover_sql_databases(self) -> List[CloudResource]:
        """Simulate Azure SQL discovery"""
        databases = []
        
        databases.append(CloudResource(
            id="azure-sql-prod",
            name="prod-sql-server",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.DATABASE,
            arn="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/prod-sql-server",
            data_sensitivity=DataSensitivity.RESTRICTED,
            exposure_level=ExposureLevel.INTERNET,
            criticality_score=0.9,
            config=ResourceConfiguration(
                raw_config={
                    "public_network_access": "Enabled",  # Misconfigured!
                    "minimal_tls_version": "1.0",  # Outdated!
                    "auditing_enabled": False,  # Misconfigured!
                    "threat_detection_enabled": False,
                    "firewall_rules": [
                        {"name": "AllowAll", "start_ip": "0.0.0.0", "end_ip": "255.255.255.255"}  # Wide open!
                    ]
                },
                encryption_enabled=True,
                public_access=True,
                logging_enabled=False,
                ports_open=[1433],
            ),
            metadata=ResourceMetadata(
                region="eastus",
                project_id="sub-123",
                tags={"Environment": "production", "DataType": "customer"},
            ),
            connected_to=["azure-vm-webserver"],
        ))
        
        return databases
    
    def _discover_key_vaults(self) -> List[CloudResource]:
        """Simulate Azure Key Vault discovery"""
        vaults = []
        
        vaults.append(CloudResource(
            id="azure-kv-prod",
            name="prod-keyvault",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.KEY_VAULT,
            arn="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/prod-keyvault",
            data_sensitivity=DataSensitivity.RESTRICTED,
            exposure_level=ExposureLevel.VPC_INTERNAL,
            criticality_score=0.95,
            config=ResourceConfiguration(
                raw_config={
                    "soft_delete_enabled": False,  # Misconfigured!
                    "purge_protection_enabled": False,  # Misconfigured!
                    "network_acls": {
                        "default_action": "Allow"  # Too permissive!
                    },
                    "access_policies": [{
                        "object_id": "user-123",
                        "permissions": {
                            "keys": ["all"],
                            "secrets": ["all"],
                            "certificates": ["all"]
                        }
                    }]
                },
                encryption_enabled=True,
                logging_enabled=False,
            ),
            metadata=ResourceMetadata(
                region="eastus",
                project_id="sub-123",
                tags={"Environment": "production"},
            ),
        ))
        
        return vaults
    
    def _discover_network_security_groups(self) -> List[CloudResource]:
        """Simulate Azure NSG discovery"""
        nsgs = []
        
        nsgs.append(CloudResource(
            id="azure-nsg-webserver",
            name="nsg-webserver",
            provider=CloudProvider.AZURE,
            resource_type=ResourceType.SECURITY_GROUP,
            arn="/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-webserver",
            data_sensitivity=DataSensitivity.PUBLIC,
            exposure_level=ExposureLevel.INTERNET,
            criticality_score=0.7,
            config=ResourceConfiguration(
                raw_config={
                    "security_rules": [
                        {
                            "name": "AllowSSH",
                            "protocol": "TCP",
                            "destination_port": "22",
                            "source_address_prefix": "*",  # From anywhere!
                            "access": "Allow"
                        },
                        {
                            "name": "AllowRDP",
                            "protocol": "TCP",
                            "destination_port": "3389",
                            "source_address_prefix": "*",  # From anywhere!
                            "access": "Allow"
                        }
                    ]
                },
                ports_open=[22, 80, 443, 3389],
            ),
            metadata=ResourceMetadata(
                region="eastus",
                project_id="sub-123",
            ),
            connected_to=["azure-vm-webserver"],
        ))
        
        return nsgs
