"""
IaC Patch Generator

Generates Infrastructure as Code patches for remediation.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import uuid
import textwrap

from ..models.misconfiguration import Misconfiguration, MisconfigCategory
from ..models.remediation import IaCPatch


@dataclass
class PatchResult:
    """Result of generating a patch"""
    success: bool
    patch: Optional[IaCPatch]
    error: Optional[str]


class IaCPatchGenerator:
    """
    Generates IaC patches for common misconfigurations.
    
    Supports:
    - Terraform
    - CloudFormation
    - Kubernetes manifests
    """
    
    def __init__(self):
        self.terraform_templates = self._init_terraform_templates()
        self.k8s_templates = self._init_k8s_templates()
    
    def generate_patch(
        self,
        misconfiguration: Misconfiguration,
        format: str = "terraform"
    ) -> PatchResult:
        """
        Generate an IaC patch for a misconfiguration.
        """
        try:
            if format == "terraform":
                patch = self._generate_terraform_patch(misconfiguration)
            elif format == "kubernetes":
                patch = self._generate_k8s_patch(misconfiguration)
            else:
                return PatchResult(False, None, f"Unsupported format: {format}")
            
            if patch:
                return PatchResult(True, patch, None)
            else:
                return PatchResult(False, None, "No patch template available for this issue")
        except Exception as e:
            return PatchResult(False, None, str(e))
    
    def generate_batch(
        self,
        misconfigurations: List[Misconfiguration],
        format: str = "terraform"
    ) -> List[PatchResult]:
        """Generate patches for multiple misconfigurations"""
        return [self.generate_patch(m, format) for m in misconfigurations]
    
    def _init_terraform_templates(self) -> Dict[str, Dict[str, str]]:
        """Initialize Terraform patch templates"""
        return {
            "s3_public_access": {
                "before": textwrap.dedent('''
                    resource "aws_s3_bucket" "{name}" {
                      bucket = "{bucket_name}"
                    }
                ''').strip(),
                "after": textwrap.dedent('''
                    resource "aws_s3_bucket" "{name}" {
                      bucket = "{bucket_name}"
                    }
                    
                    resource "aws_s3_bucket_public_access_block" "{name}_public_access_block" {
                      bucket = aws_s3_bucket.{name}.id
                    
                      block_public_acls       = true
                      block_public_policy     = true
                      ignore_public_acls      = true
                      restrict_public_buckets = true
                    }
                ''').strip(),
            },
            "s3_encryption": {
                "before": textwrap.dedent('''
                    resource "aws_s3_bucket" "{name}" {
                      bucket = "{bucket_name}"
                    }
                ''').strip(),
                "after": textwrap.dedent('''
                    resource "aws_s3_bucket" "{name}" {
                      bucket = "{bucket_name}"
                    }
                    
                    resource "aws_s3_bucket_server_side_encryption_configuration" "{name}_encryption" {
                      bucket = aws_s3_bucket.{name}.id
                    
                      rule {
                        apply_server_side_encryption_by_default {
                          sse_algorithm     = "aws:kms"
                          kms_master_key_id = aws_kms_key.{name}_key.arn
                        }
                        bucket_key_enabled = true
                      }
                    }
                ''').strip(),
            },
            "rds_public_access": {
                "before": textwrap.dedent('''
                    resource "aws_db_instance" "{name}" {
                      identifier          = "{db_name}"
                      publicly_accessible = true
                    }
                ''').strip(),
                "after": textwrap.dedent('''
                    resource "aws_db_instance" "{name}" {
                      identifier          = "{db_name}"
                      publicly_accessible = false
                      storage_encrypted   = true
                      
                      # Add to private subnet
                      db_subnet_group_name = aws_db_subnet_group.private.name
                    }
                ''').strip(),
            },
            "security_group_restrict": {
                "before": textwrap.dedent('''
                    resource "aws_security_group_rule" "allow_ssh" {
                      type              = "ingress"
                      from_port         = 22
                      to_port           = 22
                      protocol          = "tcp"
                      cidr_blocks       = ["0.0.0.0/0"]
                      security_group_id = aws_security_group.main.id
                    }
                ''').strip(),
                "after": textwrap.dedent('''
                    resource "aws_security_group_rule" "allow_ssh" {
                      type              = "ingress"
                      from_port         = 22
                      to_port           = 22
                      protocol          = "tcp"
                      cidr_blocks       = ["10.0.0.0/8"]  # Restrict to internal network
                      security_group_id = aws_security_group.main.id
                      description       = "SSH access from internal network only"
                    }
                ''').strip(),
            },
        }
    
    def _init_k8s_templates(self) -> Dict[str, Dict[str, str]]:
        """Initialize Kubernetes patch templates"""
        return {
            "privileged_container": {
                "before": textwrap.dedent('''
                    spec:
                      containers:
                        - name: webapp
                          image: webapp:latest
                          securityContext:
                            privileged: true
                ''').strip(),
                "after": textwrap.dedent('''
                    spec:
                      containers:
                        - name: webapp
                          image: webapp:v1.2.3  # Pin to specific version
                          securityContext:
                            privileged: false
                            runAsNonRoot: true
                            runAsUser: 1000
                            allowPrivilegeEscalation: false
                            readOnlyRootFilesystem: true
                            capabilities:
                              drop:
                                - ALL
                ''').strip(),
            },
            "resource_limits": {
                "before": textwrap.dedent('''
                    spec:
                      containers:
                        - name: webapp
                          image: webapp:latest
                ''').strip(),
                "after": textwrap.dedent('''
                    spec:
                      containers:
                        - name: webapp
                          image: webapp:v1.2.3
                          resources:
                            limits:
                              cpu: "500m"
                              memory: "256Mi"
                            requests:
                              cpu: "100m"
                              memory: "128Mi"
                ''').strip(),
            },
            "network_policy": {
                "before": textwrap.dedent('''
                    # No network policy defined
                ''').strip(),
                "after": textwrap.dedent('''
                    apiVersion: networking.k8s.io/v1
                    kind: NetworkPolicy
                    metadata:
                      name: default-deny-ingress
                      namespace: production
                    spec:
                      podSelector: {}
                      policyTypes:
                        - Ingress
                      ingress:
                        - from:
                            - namespaceSelector:
                                matchLabels:
                                  name: production
                ''').strip(),
            },
        }
    
    def _generate_terraform_patch(self, misc: Misconfiguration) -> Optional[IaCPatch]:
        """Generate Terraform patch"""
        title_lower = misc.title.lower()
        resource_name = misc.resource_name.replace("-", "_").replace(".", "_")
        
        template = None
        if "s3" in title_lower and "public" in title_lower:
            template = self.terraform_templates.get("s3_public_access")
        elif "encrypt" in title_lower and ("s3" in title_lower or "storage" in title_lower):
            template = self.terraform_templates.get("s3_encryption")
        elif "database" in title_lower and "public" in title_lower:
            template = self.terraform_templates.get("rds_public_access")
        elif "security group" in title_lower or "unrestricted" in title_lower:
            template = self.terraform_templates.get("security_group_restrict")
        
        if not template:
            return self._generate_generic_terraform_patch(misc)
        
        before = template["before"].format(name=resource_name, bucket_name=misc.resource_name, db_name=misc.resource_name)
        after = template["after"].format(name=resource_name, bucket_name=misc.resource_name, db_name=misc.resource_name)
        
        diff = self._generate_diff(before, after)
        
        return IaCPatch(
            id=f"patch-{uuid.uuid4().hex[:8]}",
            format="terraform",
            file_path=f"modules/{misc.resource_type}/main.tf",
            original_content=before,
            patched_content=after,
            diff=diff,
            description=f"Security fix for {misc.title}",
        )
    
    def _generate_k8s_patch(self, misc: Misconfiguration) -> Optional[IaCPatch]:
        """Generate Kubernetes manifest patch"""
        title_lower = misc.title.lower()
        
        template = None
        if "privileged" in title_lower or "escalation" in title_lower:
            template = self.k8s_templates.get("privileged_container")
        elif "resource limit" in title_lower or "no limit" in title_lower:
            template = self.k8s_templates.get("resource_limits")
        elif "network policy" in title_lower:
            template = self.k8s_templates.get("network_policy")
        
        if not template:
            return self._generate_generic_k8s_patch(misc)
        
        diff = self._generate_diff(template["before"], template["after"])
        
        return IaCPatch(
            id=f"patch-{uuid.uuid4().hex[:8]}",
            format="kubernetes",
            file_path=f"k8s/deployments/{misc.resource_name}.yaml",
            original_content=template["before"],
            patched_content=template["after"],
            diff=diff,
            description=f"Security fix for {misc.title}",
        )
    
    def _generate_generic_terraform_patch(self, misc: Misconfiguration) -> IaCPatch:
        """Generate a generic Terraform patch suggestion"""
        resource_name = misc.resource_name.replace("-", "_")
        
        original = f"# Current configuration for {misc.resource_name}\n# Review needed"
        patched = textwrap.dedent(f'''
            # Recommended fix for: {misc.title}
            # Apply the following security configuration:
            
            # 1. Review the current resource configuration
            # 2. Apply security best practices
            # 3. Test changes in a non-production environment first
            
            # Example security improvements:
            # - Enable encryption at rest
            # - Restrict network access
            # - Enable logging and monitoring
        ''').strip()
        
        return IaCPatch(
            id=f"patch-{uuid.uuid4().hex[:8]}",
            format="terraform",
            file_path=f"modules/{misc.resource_type}/main.tf",
            original_content=original,
            patched_content=patched,
            diff=self._generate_diff(original, patched),
            description=f"Generic security guidance for {misc.title}",
        )
    
    def _generate_generic_k8s_patch(self, misc: Misconfiguration) -> IaCPatch:
        """Generate a generic Kubernetes patch suggestion"""
        patched = textwrap.dedent(f'''
            # Security fix for: {misc.title}
            # Apply the following to your deployment:
            
            spec:
              containers:
                - name: your-container
                  securityContext:
                    runAsNonRoot: true
                    allowPrivilegeEscalation: false
                    readOnlyRootFilesystem: true
                    capabilities:
                      drop:
                        - ALL
        ''').strip()
        
        return IaCPatch(
            id=f"patch-{uuid.uuid4().hex[:8]}",
            format="kubernetes",
            file_path=f"k8s/deployments/{misc.resource_name}.yaml",
            original_content="# Current configuration",
            patched_content=patched,
            diff=self._generate_diff("# Current configuration", patched),
            description=f"Security guidance for {misc.title}",
        )
    
    def _generate_diff(self, before: str, after: str) -> str:
        """Generate a simple diff between before and after"""
        before_lines = before.split("\n")
        after_lines = after.split("\n")
        
        diff_lines = []
        diff_lines.append(f"--- before")
        diff_lines.append(f"+++ after")
        
        for line in before_lines:
            diff_lines.append(f"- {line}")
        
        diff_lines.append("")
        
        for line in after_lines:
            diff_lines.append(f"+ {line}")
        
        return "\n".join(diff_lines)
