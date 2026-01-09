"""
Base Cloud Provider Interface

Abstract interface for multi-cloud asset discovery.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from ..models.cloud_resource import CloudResource, ResourceType, CloudProvider


class BaseCloudProvider(ABC):
    """
    Abstract base class for cloud provider implementations.
    Each cloud provider (AWS, Azure, GCP) extends this class.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the cloud provider.
        
        Args:
            config: Provider-specific configuration (credentials, regions, etc.)
        """
        self.config = config or {}
        self.resources: Dict[str, CloudResource] = {}
        self._initialized = False
    
    @property
    @abstractmethod
    def provider_name(self) -> CloudProvider:
        """Return the provider identifier"""
        pass
    
    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to the cloud provider.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def discover_resources(self, resource_types: Optional[List[ResourceType]] = None) -> List[CloudResource]:
        """
        Discover all resources in the cloud environment.
        
        Args:
            resource_types: Optional filter for specific resource types
            
        Returns:
            List of discovered CloudResource objects
        """
        pass
    
    @abstractmethod
    async def get_resource_config(self, resource_id: str) -> Dict[str, Any]:
        """
        Get detailed configuration for a specific resource.
        
        Args:
            resource_id: The resource identifier
            
        Returns:
            Dictionary containing resource configuration
        """
        pass
    
    @abstractmethod
    async def get_resource_relationships(self, resource_id: str) -> List[tuple]:
        """
        Get relationships for a specific resource.
        
        Args:
            resource_id: The resource identifier
            
        Returns:
            List of (target_id, relationship_type) tuples
        """
        pass
    
    async def discover_all(self) -> Dict[str, CloudResource]:
        """
        Perform full discovery of all resources and relationships.
        
        Returns:
            Dictionary of resource_id -> CloudResource
        """
        resources = await self.discover_resources()
        for resource in resources:
            self.resources[resource.id] = resource
            
            # Get relationships
            relationships = await self.get_resource_relationships(resource.id)
            for target_id, _ in relationships:
                if target_id not in resource.connected_to:
                    resource.connected_to.append(target_id)
        
        self._initialized = True
        return self.resources
    
    def get_resources_by_type(self, resource_type: ResourceType) -> List[CloudResource]:
        """Get all resources of a specific type"""
        return [r for r in self.resources.values() if r.resource_type == resource_type]
    
    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Get a specific resource by ID"""
        return self.resources.get(resource_id)
    
    def get_all_resources(self) -> List[CloudResource]:
        """Get all discovered resources"""
        return list(self.resources.values())


class MultiCloudDiscovery:
    """
    Orchestrates discovery across multiple cloud providers.
    """
    
    def __init__(self):
        self.providers: Dict[str, BaseCloudProvider] = {}
        self.all_resources: Dict[str, CloudResource] = {}
    
    def register_provider(self, provider: BaseCloudProvider) -> None:
        """Register a cloud provider for discovery"""
        self.providers[provider.provider_name.value] = provider
    
    async def discover_all_providers(self) -> Dict[str, CloudResource]:
        """
        Run discovery across all registered providers.
        
        Returns:
            Combined dictionary of all resources
        """
        for provider_name, provider in self.providers.items():
            await provider.connect()
            resources = await provider.discover_all()
            
            # Merge resources with provider prefix
            for resource_id, resource in resources.items():
                global_id = f"{provider_name}:{resource_id}"
                self.all_resources[global_id] = resource
        
        return self.all_resources
    
    def get_all_resources(self) -> List[CloudResource]:
        """Get all resources across all providers"""
        return list(self.all_resources.values())
    
    def get_resources_by_provider(self, provider: CloudProvider) -> List[CloudResource]:
        """Get resources for a specific provider"""
        return [r for r in self.all_resources.values() if r.provider == provider]
    
    def get_resources_by_type(self, resource_type: ResourceType) -> List[CloudResource]:
        """Get resources of a specific type across all providers"""
        return [r for r in self.all_resources.values() if r.resource_type == resource_type]
