"""
Cloud Resource Data Models

Provides abstraction layer for multi-cloud resource representation.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json


class CloudProvider(str, Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    UNKNOWN = "unknown"


class ResourceType(str, Enum):
    """Types of cloud resources"""
    # Compute
    COMPUTE_INSTANCE = "compute_instance"
    CONTAINER = "container"
    SERVERLESS_FUNCTION = "serverless_function"
    KUBERNETES_POD = "kubernetes_pod"
    KUBERNETES_DEPLOYMENT = "kubernetes_deployment"
    
    # Storage
    OBJECT_STORAGE = "object_storage"
    BLOCK_STORAGE = "block_storage"
    DATABASE = "database"
    
    # Networking
    VIRTUAL_NETWORK = "virtual_network"
    SUBNET = "subnet"
    SECURITY_GROUP = "security_group"
    LOAD_BALANCER = "load_balancer"
    FIREWALL = "firewall"
    
    # Identity
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    SERVICE_ACCOUNT = "service_account"
    
    # Kubernetes
    KUBERNETES_NAMESPACE = "kubernetes_namespace"
    KUBERNETES_SERVICE = "kubernetes_service"
    KUBERNETES_CONFIGMAP = "kubernetes_configmap"
    KUBERNETES_SECRET = "kubernetes_secret"
    KUBERNETES_RBAC = "kubernetes_rbac"
    
    # Other
    API_GATEWAY = "api_gateway"
    KEY_VAULT = "key_vault"
    UNKNOWN = "unknown"


class DataSensitivity(str, Enum):
    """Data sensitivity classification"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class ExposureLevel(str, Enum):
    """Network exposure level"""
    INTERNET = "internet"
    VPC_INTERNAL = "vpc_internal"
    PRIVATE = "private"
    ISOLATED = "isolated"


@dataclass
class ResourceMetadata:
    """Metadata for a cloud resource"""
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    created_by: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    region: Optional[str] = None
    availability_zone: Optional[str] = None
    account_id: Optional[str] = None
    project_id: Optional[str] = None


@dataclass
class ResourceConfiguration:
    """Configuration state of a resource"""
    raw_config: Dict[str, Any] = field(default_factory=dict)
    encryption_enabled: bool = False
    encryption_key_id: Optional[str] = None
    public_access: bool = False
    logging_enabled: bool = False
    versioning_enabled: bool = False
    mfa_enabled: bool = False
    ports_open: List[int] = field(default_factory=list)
    protocols_allowed: List[str] = field(default_factory=list)
    
    def get_config_hash(self) -> str:
        """Generate hash of configuration for drift detection"""
        config_str = json.dumps(self.raw_config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()


@dataclass
class CloudResource:
    """
    Base class representing a cloud resource.
    Provides provider-agnostic abstraction for multi-cloud support.
    """
    id: str
    name: str
    provider: CloudProvider
    resource_type: ResourceType
    arn: Optional[str] = None  # AWS ARN or equivalent identifier
    
    # Classification
    data_sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    exposure_level: ExposureLevel = ExposureLevel.PRIVATE
    criticality_score: float = 0.5  # 0-1 scale
    
    # Configuration
    config: ResourceConfiguration = field(default_factory=ResourceConfiguration)
    metadata: ResourceMetadata = field(default_factory=ResourceMetadata)
    
    # Relationships
    parent_id: Optional[str] = None
    children_ids: List[str] = field(default_factory=list)
    connected_to: List[str] = field(default_factory=list)  # Network/access relationships
    depends_on: List[str] = field(default_factory=list)
    
    # State tracking
    last_scanned: Optional[datetime] = None
    config_history: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert resource to dictionary representation"""
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider.value,
            "resource_type": self.resource_type.value,
            "arn": self.arn,
            "data_sensitivity": self.data_sensitivity.value,
            "exposure_level": self.exposure_level.value,
            "criticality_score": self.criticality_score,
            "config": {
                "encryption_enabled": self.config.encryption_enabled,
                "public_access": self.config.public_access,
                "logging_enabled": self.config.logging_enabled,
                "ports_open": self.config.ports_open,
            },
            "metadata": {
                "region": self.metadata.region,
                "tags": self.metadata.tags,
                "account_id": self.metadata.account_id,
            },
            "relationships": {
                "parent_id": self.parent_id,
                "children_ids": self.children_ids,
                "connected_to": self.connected_to,
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CloudResource":
        """Create resource from dictionary"""
        config = ResourceConfiguration(
            encryption_enabled=data.get("config", {}).get("encryption_enabled", False),
            public_access=data.get("config", {}).get("public_access", False),
            logging_enabled=data.get("config", {}).get("logging_enabled", False),
            ports_open=data.get("config", {}).get("ports_open", []),
            raw_config=data.get("config", {}).get("raw_config", {}),
        )
        
        metadata = ResourceMetadata(
            region=data.get("metadata", {}).get("region"),
            tags=data.get("metadata", {}).get("tags", {}),
            account_id=data.get("metadata", {}).get("account_id"),
        )
        
        return cls(
            id=data["id"],
            name=data["name"],
            provider=CloudProvider(data.get("provider", "unknown")),
            resource_type=ResourceType(data.get("resource_type", "unknown")),
            arn=data.get("arn"),
            data_sensitivity=DataSensitivity(data.get("data_sensitivity", "unknown")),
            exposure_level=ExposureLevel(data.get("exposure_level", "private")),
            criticality_score=data.get("criticality_score", 0.5),
            config=config,
            metadata=metadata,
            parent_id=data.get("relationships", {}).get("parent_id"),
            children_ids=data.get("relationships", {}).get("children_ids", []),
            connected_to=data.get("relationships", {}).get("connected_to", []),
        )


@dataclass
class ResourceGraph:
    """
    Graph structure representing relationships between cloud resources.
    Used for attack path analysis and blast radius calculation.
    """
    resources: Dict[str, CloudResource] = field(default_factory=dict)
    edges: List[tuple] = field(default_factory=list)  # (source_id, target_id, relationship_type)
    
    def add_resource(self, resource: CloudResource) -> None:
        """Add a resource to the graph"""
        self.resources[resource.id] = resource
    
    def add_edge(self, source_id: str, target_id: str, relationship: str = "connected") -> None:
        """Add a relationship edge between resources"""
        self.edges.append((source_id, target_id, relationship))
    
    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Get a resource by ID"""
        return self.resources.get(resource_id)
    
    def get_connected_resources(self, resource_id: str) -> List[CloudResource]:
        """Get all resources connected to a given resource"""
        connected_ids = set()
        for source, target, _ in self.edges:
            if source == resource_id:
                connected_ids.add(target)
            elif target == resource_id:
                connected_ids.add(source)
        return [self.resources[rid] for rid in connected_ids if rid in self.resources]
    
    def get_resources_by_type(self, resource_type: ResourceType) -> List[CloudResource]:
        """Get all resources of a specific type"""
        return [r for r in self.resources.values() if r.resource_type == resource_type]
    
    def get_public_resources(self) -> List[CloudResource]:
        """Get all publicly exposed resources"""
        return [r for r in self.resources.values() 
                if r.exposure_level == ExposureLevel.INTERNET or r.config.public_access]


@dataclass
class ConfigurationSnapshot:
    """Snapshot of configuration state for drift detection"""
    resource_id: str
    timestamp: datetime
    config_hash: str
    config_data: Dict[str, Any]
    
    @classmethod
    def from_resource(cls, resource: CloudResource) -> "ConfigurationSnapshot":
        """Create snapshot from current resource state"""
        return cls(
            resource_id=resource.id,
            timestamp=datetime.now(),
            config_hash=resource.config.get_config_hash(),
            config_data=resource.config.raw_config.copy()
        )


@dataclass
class ConfigurationDrift:
    """Represents a configuration drift event"""
    resource_id: str
    resource_name: str
    detected_at: datetime
    previous_snapshot: ConfigurationSnapshot
    current_snapshot: ConfigurationSnapshot
    changed_fields: List[str]
    severity: str = "medium"  # low, medium, high, critical
    
    def get_diff(self) -> Dict[str, Any]:
        """Get the differences between snapshots"""
        prev = self.previous_snapshot.config_data
        curr = self.current_snapshot.config_data
        diff = {}
        
        all_keys = set(prev.keys()) | set(curr.keys())
        for key in all_keys:
            if prev.get(key) != curr.get(key):
                diff[key] = {
                    "previous": prev.get(key),
                    "current": curr.get(key)
                }
        return diff
