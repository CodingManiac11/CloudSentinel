# CloudSentinel

**Next-Generation Cloud Misconfiguration Security Scanner**

CloudSentinel is an intelligent, context-aware security platform that goes beyond traditional rule-based CSPM tools. It thinks like an attacker and acts like a security engineer.

## 🚀 Key Features

### Attack-Graph-Driven Prioritization
- Correlates low-risk issues into realistic attack paths
- Shows HOW misconfigurations can be chained together
- MITRE ATT&CK mapping for each attack scenario

### Predictive Misconfiguration Detection
- Anticipates future issues based on patterns
- Permission creep detection before it becomes critical
- Configuration drift trajectory analysis

### AI-Assisted Root Cause Analysis
- Identifies WHY misconfigurations occur
- Process, automation, training, and tooling gap detection
- Systemic issue identification

### Autonomous Remediation with Guardrails
- Auto-fix safe issues with configurable guardrails
- Human-in-the-loop for high-risk changes
- Rollback capability for all remediations

### Cross-Cloud Risk Normalization
- Unified risk scoring across AWS, Azure, and Kubernetes
- Consistent compliance mapping
- Multi-cloud security posture comparison

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/cloudsentinel/cloudsentinel.git
cd cloudsentinel

# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

## 🔧 Quick Start

### CLI Scan
```bash
# Run a demo scan with simulated infrastructure
cloudsentinel scan --demo

# Scan specific providers
cloudsentinel scan --provider aws --provider azure

# Export results to JSON
cloudsentinel scan --demo --output results.json
```

### Python API
```python
from src.scanner import CloudSentinel
import asyncio

async def run_scan():
    scanner = CloudSentinel()
    result = await scanner.scan(providers=["aws", "azure"], demo_mode=True)
    print(f"Grade: {result['overall_grade']}")
    print(f"Risk Score: {result['overall_risk_score']}/100")
    
asyncio.run(run_scan())
```

### REST API
```bash
# Start the API server
cloudsentinel serve --port 8000

# Create a scan
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"providers": ["aws"], "demo_mode": true}'

# Get results
curl http://localhost:8000/scans/{scan_id}
```

## 🏗️ Architecture

```
cloudsentinel/
├── src/
│   ├── models/           # Core data models
│   ├── discovery/        # Multi-cloud asset discovery
│   ├── detection/        # Misconfiguration detection
│   │   └── rules/        # Detection rules
│   ├── risk/             # Risk intelligence
│   ├── ai/               # AI-powered features
│   ├── remediation/      # Remediation system
│   ├── api/              # REST API
│   └── cli/              # Command-line interface
├── tests/                # Test suite
└── demo/                 # Demo scripts
```

## 🎯 Demo

Run the interactive demo to see all features:

```bash
cd demo
python run_demo.py
```

The demo showcases:
1. Multi-cloud resource discovery (AWS, Azure, Kubernetes)
2. Misconfiguration detection across 20+ rule categories
3. Attack path analysis and visualization
4. Predictive security alerts
5. Root cause analysis
6. Autonomous remediation decisions
7. IaC patch generation

## 📊 Detection Rules

CloudSentinel includes detection rules for:

| Category | Examples |
|----------|----------|
| **Public Exposure** | Public S3 buckets, databases, storage accounts |
| **IAM Security** | Over-privileged roles, missing MFA, stale keys |
| **Network Security** | Open security groups, missing network policies |
| **Encryption** | Unencrypted storage, databases, secrets |
| **Kubernetes** | Privileged containers, host access, latest tags |

## 🔐 Supported Platforms

- **AWS**: S3, EC2, RDS, IAM, Lambda, EKS, Security Groups
- **Azure**: Storage, VMs, SQL, Key Vault, NSG
- **Kubernetes**: Deployments, Pods, Secrets, RBAC, Network Policies

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test class
pytest tests/test_scanner.py::TestDetectionEngine -v
```

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.
