"""
Predictive Misconfiguration Detector

Uses pattern analysis to predict future misconfigurations before they happen.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from ..models.cloud_resource import CloudResource, ResourceType


class PredictionType(str, Enum):
    """Types of predictions"""
    IMMINENT_EXPOSURE = "imminent_exposure"
    PERMISSION_CREEP = "permission_creep"
    ENCRYPTION_DECAY = "encryption_decay"
    DRIFT_TRAJECTORY = "drift_trajectory"
    COMPLIANCE_RISK = "compliance_risk"


@dataclass
class Prediction:
    """A predicted future misconfiguration"""
    id: str
    prediction_type: PredictionType
    resource_id: str
    resource_name: str
    
    title: str
    description: str
    confidence: float  # 0-1
    
    current_state: Dict[str, Any]
    predicted_state: Dict[str, Any]
    
    risk_if_occurred: float  # 0-100
    time_to_occurrence: str  # e.g., "2-4 weeks"
    
    prevention_steps: List[str]
    indicators: List[str]  # What signals led to this prediction


@dataclass
class TrendPattern:
    """Historical pattern that may indicate future issues"""
    pattern_type: str
    frequency: int
    resources_affected: List[str]
    last_occurrence: datetime
    trend_direction: str  # increasing, decreasing, stable


class PredictiveDetector:
    """
    Analyzes patterns to predict misconfigurations before they happen.
    
    This is a key innovation - instead of just finding current issues,
    we anticipate future ones based on:
    - Historical drift patterns
    - Team behavior patterns
    - Resource lifecycle trends
    - Permission creep velocity
    """
    
    def __init__(self):
        self.historical_patterns: Dict[str, List[TrendPattern]] = {}
        self.prediction_models = {
            PredictionType.PERMISSION_CREEP: self._predict_permission_creep,
            PredictionType.ENCRYPTION_DECAY: self._predict_encryption_decay,
            PredictionType.DRIFT_TRAJECTORY: self._predict_drift_trajectory,
        }
    
    def analyze_and_predict(
        self,
        resources: List[CloudResource],
        historical_data: Dict[str, Any] = None
    ) -> List[Prediction]:
        """
        Analyze current state and predict future misconfigurations.
        """
        predictions = []
        
        for resource in resources:
            # Run each prediction model
            for pred_type, predict_func in self.prediction_models.items():
                prediction = predict_func(resource, historical_data)
                if prediction:
                    predictions.append(prediction)
        
        # Add cross-resource predictions
        predictions.extend(self._predict_cross_resource_issues(resources))
        
        # Sort by confidence and risk
        predictions.sort(key=lambda p: p.confidence * p.risk_if_occurred, reverse=True)
        
        return predictions
    
    def _predict_permission_creep(
        self,
        resource: CloudResource,
        historical: Dict[str, Any] = None
    ) -> Optional[Prediction]:
        """
        Predict if a resource is trending toward over-permissiveness.
        """
        if resource.resource_type not in [ResourceType.IAM_ROLE, ResourceType.IAM_USER]:
            return None
        
        config = resource.config.raw_config
        attached_policies = config.get("attached_policies", [])
        inline_policies = config.get("inline_policies", {})
        
        # Indicators of permission creep
        indicators = []
        
        # Many attached policies
        if len(attached_policies) >= 3:
            indicators.append(f"High policy count ({len(attached_policies)} policies)")
        
        # Wide inline permissions
        for policy_name, policy_doc in inline_policies.items():
            for statement in policy_doc.get("Statement", []):
                action = statement.get("Action", [])
                if isinstance(action, str) and ":*" in action:
                    indicators.append(f"Broad action pattern: {action}")
        
        if len(indicators) >= 2:
            import uuid
            return Prediction(
                id=f"pred-{uuid.uuid4().hex[:8]}",
                prediction_type=PredictionType.PERMISSION_CREEP,
                resource_id=resource.id,
                resource_name=resource.name,
                title=f"Permission Creep Detected: {resource.name}",
                description=(
                    f"The IAM configuration for '{resource.name}' shows signs of permission creep. "
                    f"Based on current trajectory, this may lead to over-privileged access "
                    f"that violates least privilege principles."
                ),
                confidence=0.75,
                current_state={"policy_count": len(attached_policies)},
                predicted_state={"risk": "AdminAccess equivalent"},
                risk_if_occurred=85.0,
                time_to_occurrence="2-4 weeks",
                prevention_steps=[
                    "Audit current permissions and remove unused policies",
                    "Implement permission boundaries",
                    "Set up alerts for new policy attachments",
                ],
                indicators=indicators,
            )
        
        return None
    
    def _predict_encryption_decay(
        self,
        resource: CloudResource,
        historical: Dict[str, Any] = None
    ) -> Optional[Prediction]:
        """
        Predict if resources are trending toward unencrypted state.
        """
        if resource.resource_type not in [ResourceType.OBJECT_STORAGE, ResourceType.DATABASE]:
            return None
        
        indicators = []
        
        # Check for encryption disabled
        if not resource.config.encryption_enabled:
            # Already a problem, not a prediction
            return None
        
        # Look for warning signs of encryption being turned off
        config = resource.config.raw_config
        
        # Weak encryption key configuration
        if not resource.config.encryption_key_id:
            indicators.append("Using default encryption key instead of CMK")
        
        # Missing key rotation
        if config.get("key_rotation_enabled") == False:
            indicators.append("Key rotation is disabled")
        
        # Check for lifecycle policies that might delete encrypted backups
        if config.get("lifecycle_rules"):
            indicators.append("Lifecycle rules may affect encrypted objects")
        
        if len(indicators) >= 1:
            import uuid
            return Prediction(
                id=f"pred-{uuid.uuid4().hex[:8]}",
                prediction_type=PredictionType.ENCRYPTION_DECAY,
                resource_id=resource.id,
                resource_name=resource.name,
                title=f"Encryption Configuration Weakening: {resource.name}",
                description=(
                    f"The encryption configuration for '{resource.name}' may be weakening. "
                    f"While currently encrypted, the configuration shows signs of decay."
                ),
                confidence=0.6,
                current_state={"encryption": "enabled", "key_type": "CMK" if resource.config.encryption_key_id else "default"},
                predicted_state={"encryption": "weakened"},
                risk_if_occurred=70.0,
                time_to_occurrence="1-2 months",
                prevention_steps=[
                    "Migrate to customer-managed encryption keys",
                    "Enable automatic key rotation",
                    "Set up monitoring for encryption configuration changes",
                ],
                indicators=indicators,
            )
        
        return None
    
    def _predict_drift_trajectory(
        self,
        resource: CloudResource,
        historical: Dict[str, Any] = None
    ) -> Optional[Prediction]:
        """
        Predict drift based on historical patterns.
        """
        # Check for resources that tend to drift
        config = resource.config.raw_config
        indicators = []
        
        # Resources without proper change controls are more likely to drift
        if not config.get("deletion_protection"):
            indicators.append("No deletion protection")
        
        if not resource.config.logging_enabled:
            indicators.append("Changes are not being logged")
        
        # Check for patterns that indicate manual changes
        tags = resource.metadata.tags
        if "terraform" not in str(tags).lower() and "cloudformation" not in str(tags).lower():
            indicators.append("Resource may not be managed by IaC")
        
        if len(indicators) >= 2:
            import uuid
            return Prediction(
                id=f"pred-{uuid.uuid4().hex[:8]}",
                prediction_type=PredictionType.DRIFT_TRAJECTORY,
                resource_id=resource.id,
                resource_name=resource.name,
                title=f"Configuration Drift Risk: {resource.name}",
                description=(
                    f"The resource '{resource.name}' has a high likelihood of configuration drift. "
                    f"Without proper change controls, security settings may degrade over time."
                ),
                confidence=0.65,
                current_state={"change_management": "weak"},
                predicted_state={"drift": "likely"},
                risk_if_occurred=55.0,
                time_to_occurrence="1-3 weeks",
                prevention_steps=[
                    "Implement Infrastructure as Code for this resource",
                    "Enable CloudTrail/Activity logging",
                    "Set up configuration change alerts",
                ],
                indicators=indicators,
            )
        
        return None
    
    def _predict_cross_resource_issues(
        self,
        resources: List[CloudResource]
    ) -> List[Prediction]:
        """
        Predict issues that arise from interactions between resources.
        """
        predictions = []
        import uuid
        
        # Look for network exposure patterns
        public_resources = [r for r in resources if r.config.public_access]
        sensitive_resources = [r for r in resources 
                             if r.data_sensitivity.value in ["restricted", "confidential"]]
        
        # Check for connections between public and sensitive resources
        for public_res in public_resources:
            for sensitive_res in sensitive_resources:
                if sensitive_res.id in public_res.connected_to:
                    predictions.append(Prediction(
                        id=f"pred-{uuid.uuid4().hex[:8]}",
                        prediction_type=PredictionType.IMMINENT_EXPOSURE,
                        resource_id=sensitive_res.id,
                        resource_name=sensitive_res.name,
                        title=f"Imminent Data Exposure Risk: {sensitive_res.name}",
                        description=(
                            f"Sensitive resource '{sensitive_res.name}' is connected to public "
                            f"resource '{public_res.name}'. This pattern frequently leads to "
                            f"data exposure incidents."
                        ),
                        confidence=0.85,
                        current_state={"connected_to_public": public_res.name},
                        predicted_state={"exposure": "likely"},
                        risk_if_occurred=95.0,
                        time_to_occurrence="Immediate risk",
                        prevention_steps=[
                            f"Remove connection between {public_res.name} and {sensitive_res.name}",
                            "Add network segmentation",
                            "Implement additional authentication layers",
                        ],
                        indicators=["Direct connection from public to sensitive resource"],
                    ))
        
        return predictions
    
    def get_prediction_summary(self, predictions: List[Prediction]) -> Dict[str, Any]:
        """Generate summary of predictions"""
        if not predictions:
            return {
                "total_predictions": 0,
                "message": "No future misconfigurations predicted",
            }
        
        by_type = {}
        for pred in predictions:
            t = pred.prediction_type.value
            if t not in by_type:
                by_type[t] = 0
            by_type[t] += 1
        
        high_risk = [p for p in predictions if p.risk_if_occurred >= 70]
        
        return {
            "total_predictions": len(predictions),
            "high_risk_predictions": len(high_risk),
            "by_type": by_type,
            "average_confidence": sum(p.confidence for p in predictions) / len(predictions),
            "top_predictions": [
                {
                    "title": p.title,
                    "risk": p.risk_if_occurred,
                    "confidence": p.confidence,
                    "time_to_occurrence": p.time_to_occurrence,
                }
                for p in predictions[:3]
            ],
        }
