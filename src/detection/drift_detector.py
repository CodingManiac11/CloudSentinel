"""
Configuration Drift Detector

Detects changes in resource configurations over time.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field
import json
import hashlib

from ..models.cloud_resource import CloudResource, ConfigurationSnapshot, ConfigurationDrift


@dataclass
class DriftReport:
    """Report of all detected configuration drifts"""
    report_id: str
    generated_at: datetime
    drifts: List[ConfigurationDrift]
    summary: Dict[str, int]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "total_drifts": len(self.drifts),
            "summary": self.summary,
            "drifts": [
                {
                    "resource_id": d.resource_id,
                    "resource_name": d.resource_name,
                    "severity": d.severity,
                    "changed_fields": d.changed_fields,
                    "detected_at": d.detected_at.isoformat(),
                }
                for d in self.drifts
            ]
        }


class DriftDetector:
    """
    Detects configuration drift by comparing current state to previous snapshots.
    
    This helps identify:
    - Unauthorized changes
    - Configuration regression
    - Security control removal
    """
    
    def __init__(self):
        # In-memory storage for snapshots (in production, use a database)
        self.snapshots: Dict[str, List[ConfigurationSnapshot]] = {}
        
        # Fields that indicate security-relevant changes
        self.security_sensitive_fields = {
            "public_access", "publicly_accessible", "encryption_enabled",
            "storage_encrypted", "logging_enabled", "mfa_enabled",
            "bucket_policy", "inbound_rules", "security_rules",
            "attached_policies", "firewall_rules", "network_acls",
            "security_context", "privileged", "host_network",
        }
    
    def take_snapshot(self, resource: CloudResource) -> ConfigurationSnapshot:
        """
        Take a configuration snapshot of a resource.
        """
        snapshot = ConfigurationSnapshot.from_resource(resource)
        
        # Store snapshot
        if resource.id not in self.snapshots:
            self.snapshots[resource.id] = []
        self.snapshots[resource.id].append(snapshot)
        
        # Keep only last 10 snapshots per resource
        if len(self.snapshots[resource.id]) > 10:
            self.snapshots[resource.id] = self.snapshots[resource.id][-10:]
        
        return snapshot
    
    def detect_drift(self, resource: CloudResource) -> Optional[ConfigurationDrift]:
        """
        Compare current resource configuration to the last snapshot.
        Returns a ConfigurationDrift if changes are detected.
        """
        if resource.id not in self.snapshots or not self.snapshots[resource.id]:
            # No previous snapshot, take one now
            self.take_snapshot(resource)
            return None
        
        # Get previous snapshot
        previous = self.snapshots[resource.id][-1]
        
        # Create current snapshot
        current = ConfigurationSnapshot.from_resource(resource)
        
        # Compare hashes
        if previous.config_hash == current.config_hash:
            return None  # No drift
        
        # Find changed fields
        changed_fields = self._find_changed_fields(
            previous.config_data, 
            current.config_data
        )
        
        if not changed_fields:
            return None
        
        # Determine severity based on changed fields
        severity = self._calculate_drift_severity(changed_fields)
        
        # Create drift record
        drift = ConfigurationDrift(
            resource_id=resource.id,
            resource_name=resource.name,
            detected_at=datetime.now(),
            previous_snapshot=previous,
            current_snapshot=current,
            changed_fields=changed_fields,
            severity=severity
        )
        
        # Store new snapshot
        self.snapshots[resource.id].append(current)
        
        return drift
    
    def detect_all_drifts(self, resources: List[CloudResource]) -> DriftReport:
        """
        Detect drift across all resources.
        """
        import uuid
        
        drifts = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for resource in resources:
            drift = self.detect_drift(resource)
            if drift:
                drifts.append(drift)
                severity_counts[drift.severity] += 1
        
        return DriftReport(
            report_id=f"drift-{uuid.uuid4().hex[:8]}",
            generated_at=datetime.now(),
            drifts=drifts,
            summary=severity_counts
        )
    
    def get_resource_history(self, resource_id: str) -> List[ConfigurationSnapshot]:
        """Get all snapshots for a resource"""
        return self.snapshots.get(resource_id, [])
    
    def _find_changed_fields(
        self, 
        previous: Dict[str, Any], 
        current: Dict[str, Any],
        prefix: str = ""
    ) -> List[str]:
        """Recursively find changed fields between two configurations"""
        changed = []
        all_keys = set(previous.keys()) | set(current.keys())
        
        for key in all_keys:
            field_path = f"{prefix}.{key}" if prefix else key
            prev_value = previous.get(key)
            curr_value = current.get(key)
            
            if prev_value != curr_value:
                # If both are dicts, recurse
                if isinstance(prev_value, dict) and isinstance(curr_value, dict):
                    changed.extend(self._find_changed_fields(prev_value, curr_value, field_path))
                else:
                    changed.append(field_path)
        
        return changed
    
    def _calculate_drift_severity(self, changed_fields: List[str]) -> str:
        """Calculate severity based on what fields changed"""
        # Check if any security-sensitive fields changed
        sensitive_changes = []
        for field in changed_fields:
            field_name = field.split(".")[-1]
            if field_name in self.security_sensitive_fields:
                sensitive_changes.append(field)
        
        if len(sensitive_changes) >= 3:
            return "critical"
        elif len(sensitive_changes) >= 2:
            return "high"
        elif len(sensitive_changes) >= 1:
            return "medium"
        else:
            return "low"
    
    def simulate_drift_for_demo(self, resources: List[CloudResource]) -> DriftReport:
        """
        Simulate drift detection for demo purposes.
        Creates fake "previous" snapshots showing security degradation.
        """
        import uuid
        
        drifts = []
        
        # Simulate drift on a few resources
        for resource in resources[:3]:
            if resource.id not in self.snapshots:
                # Create a "better" previous config
                previous_config = resource.config.raw_config.copy()
                
                # Simulate security improvements that were "removed"
                if "public_access" in str(previous_config) or resource.config.public_access:
                    previous_config["public_access_block"] = {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                    }
                
                previous_snapshot = ConfigurationSnapshot(
                    resource_id=resource.id,
                    timestamp=datetime.now(),
                    config_hash="previous-" + hashlib.sha256(json.dumps(previous_config).encode()).hexdigest()[:16],
                    config_data=previous_config
                )
                
                current_snapshot = ConfigurationSnapshot.from_resource(resource)
                
                drift = ConfigurationDrift(
                    resource_id=resource.id,
                    resource_name=resource.name,
                    detected_at=datetime.now(),
                    previous_snapshot=previous_snapshot,
                    current_snapshot=current_snapshot,
                    changed_fields=["public_access_block", "encryption_enabled"],
                    severity="high"
                )
                drifts.append(drift)
        
        return DriftReport(
            report_id=f"drift-demo-{uuid.uuid4().hex[:8]}",
            generated_at=datetime.now(),
            drifts=drifts,
            summary={"critical": 0, "high": len(drifts), "medium": 0, "low": 0}
        )
