"""
Resource Graph Builder

Builds and manages relationships between cloud resources using NetworkX.
Used for attack path analysis and blast radius calculation.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
import networkx as nx

from ..models.cloud_resource import CloudResource, ResourceType, ExposureLevel, DataSensitivity


@dataclass
class GraphEdge:
    """Represents a relationship between resources"""
    source_id: str
    target_id: str
    relationship_type: str
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class ResourceGraphBuilder:
    """
    Builds and maintains a graph of cloud resource relationships.
    Uses NetworkX for graph operations and path finding.
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.resources: Dict[str, CloudResource] = {}
        self._relationship_weights = {
            "has_access": 0.3,
            "can_assume": 0.2,
            "network_connected": 0.5,
            "contains": 0.1,
            "exposes": 0.4,
            "stores_data": 0.3,
            "manages": 0.2,
        }
    
    def add_resource(self, resource: CloudResource) -> None:
        """Add a resource as a node in the graph"""
        self.resources[resource.id] = resource
        
        # Calculate node attributes for graph analysis
        node_attrs = {
            "name": resource.name,
            "type": resource.resource_type.value,
            "provider": resource.provider.value,
            "criticality": resource.criticality_score,
            "sensitivity": resource.data_sensitivity.value,
            "exposure": resource.exposure_level.value,
            "is_public": resource.config.public_access,
            "is_internet_exposed": resource.exposure_level == ExposureLevel.INTERNET,
        }
        
        self.graph.add_node(resource.id, **node_attrs)
    
    def add_resources(self, resources: List[CloudResource]) -> None:
        """Add multiple resources to the graph"""
        for resource in resources:
            self.add_resource(resource)
        
        # Build relationships after all resources are added
        self._build_relationships()
    
    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Get a resource by ID"""
        return self.resources.get(resource_id)
    
    def add_edge(self, source_id: str, target_id: str, relationship: str, weight: float = None) -> None:
        """Add a relationship edge between resources"""
        if weight is None:
            weight = self._relationship_weights.get(relationship, 0.5)
        
        self.graph.add_edge(source_id, target_id, relationship=relationship, weight=weight)
    
    def _build_relationships(self) -> None:
        """Build relationships based on resource connections"""
        for resource in self.resources.values():
            # Add edges from connected_to list
            for target_id in resource.connected_to:
                if target_id in self.resources:
                    # Determine relationship type based on resource types
                    rel_type = self._infer_relationship_type(resource.id, target_id)
                    self.add_edge(resource.id, target_id, rel_type)
            
            # Add parent-child relationships
            if resource.parent_id and resource.parent_id in self.resources:
                self.add_edge(resource.parent_id, resource.id, "contains")
            
            for child_id in resource.children_ids:
                if child_id in self.resources:
                    self.add_edge(resource.id, child_id, "contains")
    
    def _infer_relationship_type(self, source_id: str, target_id: str) -> str:
        """Infer the relationship type between two resources"""
        source = self.resources.get(source_id)
        target = self.resources.get(target_id)
        
        if not source or not target:
            return "connected"
        
        # IAM relationships
        if source.resource_type in [ResourceType.IAM_ROLE, ResourceType.IAM_USER, ResourceType.SERVICE_ACCOUNT]:
            if target.resource_type in [ResourceType.OBJECT_STORAGE, ResourceType.DATABASE]:
                return "has_access"
            if target.resource_type == ResourceType.IAM_ROLE:
                return "can_assume"
        
        # Compute to storage relationships
        if source.resource_type in [ResourceType.COMPUTE_INSTANCE, ResourceType.SERVERLESS_FUNCTION]:
            if target.resource_type in [ResourceType.OBJECT_STORAGE, ResourceType.DATABASE]:
                return "stores_data"
            if target.resource_type == ResourceType.IAM_ROLE:
                return "can_assume"
        
        # Network relationships
        if source.resource_type == ResourceType.SECURITY_GROUP:
            return "protects"
        
        if source.resource_type == ResourceType.LOAD_BALANCER:
            return "exposes"
        
        return "network_connected"
    
    def get_public_entry_points(self) -> List[CloudResource]:
        """Get all resources that are publicly accessible (entry points for attackers)"""
        entry_points = []
        for resource_id, attrs in self.graph.nodes(data=True):
            if attrs.get("is_internet_exposed") or attrs.get("is_public"):
                if resource_id in self.resources:
                    entry_points.append(self.resources[resource_id])
        return entry_points
    
    def get_sensitive_targets(self) -> List[CloudResource]:
        """Get all resources containing sensitive data (targets for attackers)"""
        seen_ids = set()
        targets = []
        sensitive_levels = [DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED]
        
        for resource in self.resources.values():
            should_add = False
            if resource.data_sensitivity in sensitive_levels:
                should_add = True
            # Also include databases and secret stores
            if resource.resource_type in [
                ResourceType.DATABASE, 
                ResourceType.KEY_VAULT,
                ResourceType.KUBERNETES_SECRET
            ]:
                should_add = True
            
            if should_add and resource.id not in seen_ids:
                targets.append(resource)
                seen_ids.add(resource.id)
        
        return targets
    
    def find_paths(self, source_id: str, target_id: str, max_depth: int = 5) -> List[List[str]]:
        """Find all paths between two resources"""
        if source_id not in self.graph or target_id not in self.graph:
            return []
        
        try:
            paths = list(nx.all_simple_paths(self.graph, source_id, target_id, cutoff=max_depth))
            return paths
        except nx.NetworkXNoPath:
            return []
    
    def find_attack_paths(self, max_depth: int = 5) -> List[List[str]]:
        """
        Find potential attack paths from public entry points to sensitive targets.
        Returns list of paths, where each path is a list of resource IDs.
        """
        entry_points = self.get_public_entry_points()
        targets = self.get_sensitive_targets()
        
        attack_paths = []
        
        for entry in entry_points:
            for target in targets:
                if entry.id != target.id:
                    paths = self.find_paths(entry.id, target.id, max_depth)
                    attack_paths.extend(paths)
        
        # Sort by path length (shorter = more exploitable)
        attack_paths.sort(key=len)
        
        return attack_paths
    
    def calculate_blast_radius(self, resource_id: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Calculate the blast radius of a compromised resource.
        Returns the set of resources that could be affected.
        """
        if resource_id not in self.graph:
            return {"affected_resources": [], "total_count": 0, "critical_count": 0}
        
        # Find all reachable nodes from this resource
        affected = set()
        
        # BFS to find reachable nodes within max_depth
        current_level = {resource_id}
        for depth in range(max_depth):
            next_level = set()
            for node in current_level:
                for neighbor in self.graph.neighbors(node):
                    if neighbor not in affected and neighbor != resource_id:
                        affected.add(neighbor)
                        next_level.add(neighbor)
            current_level = next_level
        
        # Analyze affected resources
        affected_resources = [self.resources[rid] for rid in affected if rid in self.resources]
        critical_resources = [r for r in affected_resources if r.criticality_score >= 0.8]
        
        return {
            "affected_resources": affected_resources,
            "total_count": len(affected_resources),
            "critical_count": len(critical_resources),
            "max_criticality": max([r.criticality_score for r in affected_resources]) if affected_resources else 0,
        }
    
    def get_privilege_escalation_paths(self) -> List[List[str]]:
        """Find paths that could lead to privilege escalation"""
        escalation_paths = []
        
        # Find IAM resources
        iam_resources = [r for r in self.resources.values() 
                        if r.resource_type in [ResourceType.IAM_ROLE, ResourceType.IAM_USER, ResourceType.KUBERNETES_RBAC]]
        
        # Find paths from compute resources to high-privilege IAM resources
        compute_resources = [r for r in self.resources.values()
                           if r.resource_type in [ResourceType.COMPUTE_INSTANCE, ResourceType.SERVERLESS_FUNCTION,
                                                  ResourceType.KUBERNETES_POD]]
        
        for compute in compute_resources:
            for iam in iam_resources:
                if iam.criticality_score >= 0.8:  # High privilege
                    paths = self.find_paths(compute.id, iam.id, max_depth=3)
                    escalation_paths.extend(paths)
        
        return escalation_paths
    
    def get_cross_boundary_connections(self) -> List[Tuple[str, str]]:
        """Find connections that cross trust boundaries (e.g., public to private)"""
        cross_boundary = []
        
        for source_id, target_id in self.graph.edges():
            source = self.resources.get(source_id)
            target = self.resources.get(target_id)
            
            if not source or not target:
                continue
            
            # Check if crossing from public to private
            if source.exposure_level == ExposureLevel.INTERNET and \
               target.exposure_level in [ExposureLevel.VPC_INTERNAL, ExposureLevel.PRIVATE]:
                cross_boundary.append((source_id, target_id))
        
        return cross_boundary
    
    def to_dict(self) -> Dict[str, Any]:
        """Export graph to dictionary for visualization"""
        nodes = []
        for node_id, attrs in self.graph.nodes(data=True):
            resource = self.resources.get(node_id)
            nodes.append({
                "id": node_id,
                "label": attrs.get("name", node_id),
                "type": attrs.get("type"),
                "provider": attrs.get("provider"),
                "criticality": attrs.get("criticality", 0),
                "is_public": attrs.get("is_public", False),
            })
        
        edges = []
        for source, target, attrs in self.graph.edges(data=True):
            edges.append({
                "source": source,
                "target": target,
                "relationship": attrs.get("relationship", "connected"),
                "weight": attrs.get("weight", 1.0),
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
