"""
CloudSentinel Test Suite
"""

import pytest
import asyncio
from datetime import datetime


class TestCloudResourceModels:
    """Tests for cloud resource models"""
    
    def test_cloud_resource_creation(self):
        """Test basic cloud resource creation"""
        from src.models.cloud_resource import (
            CloudResource, CloudProvider, ResourceType,
            ResourceConfiguration, ResourceMetadata
        )
        
        resource = CloudResource(
            id="test-resource-1",
            provider=CloudProvider.AWS,
            resource_type=ResourceType.OBJECT_STORAGE,
            name="test-bucket",
            region="us-east-1",
            account_id="123456789",
            config=ResourceConfiguration(
                raw_config={"bucket": "test"},
                public_access=False,
                encryption_enabled=True,
            ),
            metadata=ResourceMetadata(tags={"env": "test"}),
        )
        
        assert resource.id == "test-resource-1"
        assert resource.provider == CloudProvider.AWS
        assert resource.config.encryption_enabled is True
    
    def test_resource_configuration(self):
        """Test resource configuration tracking"""
        from src.models.cloud_resource import ResourceConfiguration
        
        config = ResourceConfiguration(
            raw_config={"test": "value"},
            public_access=True,
            encryption_enabled=False,
            ports_open=[22, 443],
        )
        
        assert config.public_access is True
        assert 22 in config.ports_open


class TestMisconfigurationModels:
    """Tests for misconfiguration models"""
    
    def test_misconfiguration_creation(self):
        """Test misconfiguration finding creation"""
        from src.models.misconfiguration import (
            Misconfiguration, Severity, MisconfigCategory
        )
        
        misc = Misconfiguration(
            id="misc-1",
            rule_id="TEST-001",
            title="Test Misconfiguration",
            description="This is a test",
            severity=Severity.HIGH,
            category=MisconfigCategory.PUBLIC_EXPOSURE,
            resource_id="resource-1",
            resource_name="test-resource",
            resource_type="s3",
            provider="aws",
        )
        
        assert misc.severity == Severity.HIGH
        assert misc.category == MisconfigCategory.PUBLIC_EXPOSURE
    
    def test_risk_score_calculation(self):
        """Test risk score calculation from factors"""
        from src.models.misconfiguration import RiskFactors, RiskScore
        
        factors = RiskFactors(
            asset_criticality=0.8,
            data_sensitivity=0.9,
            exposure_surface=1.0,
            blast_radius=0.5,
            exploit_feasibility=0.7,
        )
        
        score = RiskScore.from_factors(factors, "Test justification")
        
        assert 0 <= score.score <= 100
        assert score.justification == "Test justification"


class TestDiscoveryProviders:
    """Tests for cloud discovery providers"""
    
    @pytest.mark.asyncio
    async def test_aws_provider_discovery(self):
        """Test AWS provider resource discovery"""
        from src.discovery.aws_provider import AWSProvider
        
        provider = AWSProvider()
        await provider.connect()
        
        resources = await provider.discover_resources()
        
        assert len(resources) > 0
        assert all(r.provider.value == "aws" for r in resources)
    
    @pytest.mark.asyncio
    async def test_azure_provider_discovery(self):
        """Test Azure provider resource discovery"""
        from src.discovery.azure_provider import AzureProvider
        
        provider = AzureProvider()
        await provider.connect()
        
        resources = await provider.discover_resources()
        
        assert len(resources) > 0
        assert all(r.provider.value == "azure" for r in resources)
    
    @pytest.mark.asyncio
    async def test_kubernetes_provider_discovery(self):
        """Test Kubernetes provider resource discovery"""
        from src.discovery.kubernetes_provider import KubernetesProvider
        
        provider = KubernetesProvider()
        await provider.connect()
        
        resources = await provider.discover_resources()
        
        assert len(resources) > 0
        assert all(r.provider.value == "kubernetes" for r in resources)


class TestResourceGraph:
    """Tests for resource graph builder"""
    
    @pytest.mark.asyncio
    async def test_graph_building(self):
        """Test resource graph construction"""
        from src.discovery.aws_provider import AWSProvider
        from src.discovery.resource_graph import ResourceGraphBuilder
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        graph = ResourceGraphBuilder()
        graph.add_resources(resources)
        
        assert graph.graph.number_of_nodes() > 0
    
    @pytest.mark.asyncio
    async def test_attack_path_finding(self):
        """Test attack path detection"""
        from src.discovery.aws_provider import AWSProvider
        from src.discovery.resource_graph import ResourceGraphBuilder
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        graph = ResourceGraphBuilder()
        graph.add_resources(resources)
        
        paths = graph.find_attack_paths()
        # Should find at least some paths in demo data
        assert isinstance(paths, list)


class TestDetectionEngine:
    """Tests for detection engine"""
    
    @pytest.mark.asyncio
    async def test_scan_resources(self):
        """Test full resource scanning"""
        from src.discovery.aws_provider import AWSProvider
        from src.detection.detection_engine import DetectionEngine
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        engine = DetectionEngine()
        result = engine.scan_resources(resources)
        
        assert result.scan_id is not None
        assert result.resource_count == len(resources)
        assert len(result.misconfigurations) > 0  # Demo data has intentional misconfigs
    
    def test_rule_registry(self):
        """Test detection rule registry"""
        from src.detection.rules.base_rule import get_rule_registry
        
        registry = get_rule_registry()
        rules = registry.get_all_rules()
        
        assert len(rules) > 0


class TestRiskAnalysis:
    """Tests for risk intelligence"""
    
    @pytest.mark.asyncio
    async def test_attack_graph_generation(self):
        """Test attack graph generation"""
        from src.discovery.aws_provider import AWSProvider
        from src.discovery.resource_graph import ResourceGraphBuilder
        from src.detection.detection_engine import DetectionEngine
        from src.risk.attack_graph import AttackGraphGenerator
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        graph = ResourceGraphBuilder()
        graph.add_resources(resources)
        
        engine = DetectionEngine()
        result = engine.scan_resources(resources)
        
        attack_gen = AttackGraphGenerator(graph)
        paths = attack_gen.generate_attack_paths(result.misconfigurations)
        
        assert isinstance(paths, list)
    
    @pytest.mark.asyncio
    async def test_prioritizer(self):
        """Test finding prioritization"""
        from src.discovery.aws_provider import AWSProvider
        from src.detection.detection_engine import DetectionEngine
        from src.risk.prioritizer import RiskPrioritizer
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        engine = DetectionEngine()
        result = engine.scan_resources(resources)
        
        prioritizer = RiskPrioritizer()
        prioritized = prioritizer.prioritize_findings(result.misconfigurations)
        
        assert len(prioritized) > 0
        # Should be sorted by priority
        if len(prioritized) > 1:
            assert prioritized[0].priority_score >= prioritized[1].priority_score


class TestAIFeatures:
    """Tests for AI-powered features"""
    
    @pytest.mark.asyncio
    async def test_predictive_detector(self):
        """Test predictive misconfiguration detection"""
        from src.discovery.aws_provider import AWSProvider
        from src.ai.predictive_detector import PredictiveDetector
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        predictor = PredictiveDetector()
        predictions = predictor.analyze_and_predict(resources)
        
        assert isinstance(predictions, list)
    
    @pytest.mark.asyncio
    async def test_root_cause_analyzer(self):
        """Test root cause analysis"""
        from src.discovery.aws_provider import AWSProvider
        from src.detection.detection_engine import DetectionEngine
        from src.ai.root_cause_analyzer import RootCauseAnalyzer
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        engine = DetectionEngine()
        result = engine.scan_resources(resources)
        
        analyzer = RootCauseAnalyzer()
        rca = analyzer.analyze(result.misconfigurations, resources)
        
        assert rca.analysis_id is not None


class TestRemediation:
    """Tests for remediation system"""
    
    @pytest.mark.asyncio
    async def test_remediation_recommender(self):
        """Test remediation recommendations"""
        from src.discovery.aws_provider import AWSProvider
        from src.detection.detection_engine import DetectionEngine
        from src.remediation.recommender import RemediationRecommender
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        engine = DetectionEngine()
        result = engine.scan_resources(resources)
        
        recommender = RemediationRecommender()
        rems = recommender.recommend_batch(result.misconfigurations[:3])
        
        assert len(rems) == 3
        for rem in rems:
            assert rem.what_is_wrong is not None
            assert rem.how_to_fix is not None
    
    @pytest.mark.asyncio
    async def test_iac_patch_generator(self):
        """Test IaC patch generation"""
        from src.discovery.aws_provider import AWSProvider
        from src.detection.detection_engine import DetectionEngine
        from src.remediation.iac_generator import IaCPatchGenerator
        
        provider = AWSProvider()
        await provider.connect()
        resources = await provider.discover_resources()
        
        engine = DetectionEngine()
        result = engine.scan_resources(resources)
        
        generator = IaCPatchGenerator()
        
        for misc in result.misconfigurations[:3]:
            patch_result = generator.generate_patch(misc, "terraform")
            assert patch_result.success or patch_result.error is not None


class TestEndToEnd:
    """End-to-end integration tests"""
    
    @pytest.mark.asyncio
    async def test_full_scan_pipeline(self):
        """Test complete scan pipeline"""
        from src.scanner import CloudSentinel
        
        scanner = CloudSentinel()
        result = await scanner.scan(providers=["aws"], demo_mode=True)
        
        assert result["scan_id"] is not None
        assert result["resources_scanned"] > 0
        assert result["overall_grade"] in ["A", "B", "C", "D", "F"]
        assert 0 <= result["overall_risk_score"] <= 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
