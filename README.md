# Zero Trust Policy Enforcement & Automated Remediation for Kubernetes

A Python-based security auditing and automated remediation system that enforces Zero Trust principles in Kubernetes clusters. The system continuously audits RBAC configurations, network policies, workload security contexts, and secret management practices against a formal security baseline, with violations mapped to **NIST SP 800-53 Rev 5**, **ISO 27001:2022**, and **CIS Kubernetes Benchmark v1.8** controls.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28+-326CE5)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Architecture
INPUT                    AUDIT ENGINE              DECISION                 REMEDIATION & OUTPUT
┌─────────────┐    ┌──────────────────────┐   ┌─────────────────┐    ┌──────────────────────┐
│ baseline.yaml│───▶│  RBAC Auditor        │──▶│ Risk Classifier │───▶│ Auto Remediation     │
│ (Zero Trust  │    │  Network Auditor     │   │ (CRIT/HIGH/     │    │ (LOW/MED via K8s API)│
│  Policy)     │    │  Trust Auditor       │   │  MED/LOW)       │    ├──────────────────────┤
├─────────────┤    │  Secrets Auditor     │   ├─────────────────┤    │ Human Review Queue   │
│ K8s Cluster  │───▶│                      │   │ Compliance      │    │ (HIGH/CRIT flagged)  │
│ (Minikube +  │    │  + Framework Mapping │   │ Scorer          │    ├──────────────────────┤
│  Calico CNI) │    │  (NIST/ISO/CIS)      │   │ (Weighted %)    │    │ YAML Manifests       │
├─────────────┤    └──────────────────────┘   └─────────────────┘    │ (Ready-to-apply)     │
│ Test         │                                                      ├──────────────────────┤
│ Namespaces   │                                                      │ HTML Dashboard       │
│ (secure/     │                                                      │ + JSON Report        │
│  insecure)   │                                                      └──────────────────────┘
└─────────────┘

## Features

- **4 Specialized Auditors** — RBAC, Network Policy, Workload Trust, and Secret Management
- **Risk-Weighted Scoring** — CRITICAL (100), HIGH (50), MEDIUM (20), LOW (5) severity classification
- **Compliance Percentage** — Weighted compliance score with per-category breakdowns
- **Multi-Framework Mapping** — Every violation mapped to NIST 800-53, ISO 27001, and CIS Kubernetes Benchmark
- **Automated Remediation** — LOW/MEDIUM violations auto-fixed via Kubernetes API
- **Human Review Queue** — HIGH/CRITICAL violations flagged with detailed remediation steps
- **YAML Manifest Generation** — Ready-to-apply fix files for every violation
- **HTML Dashboard** — Visual compliance report with severity breakdown and framework references

## Compliance Framework Coverage

| Framework | Controls Covered | Sections |
|-----------|-----------------|----------|
| NIST SP 800-53 Rev 5 | 15 controls | AC, CM, IA, SC, SI families |
| ISO 27001:2022 | 10 Annex A controls | Access Control, Technology themes |
| CIS Kubernetes Benchmark v1.8 | 8 checks | 5.1, 5.2, 5.3, 5.4 |

## Violation Types Detected

| Type | Severity | CIS | NIST | Auditor |
|------|----------|-----|------|---------|
| Cluster-admin bindings | CRITICAL | 5.1.1 | AC-6, AC-6(5) | RBAC |
| Privileged containers | CRITICAL | 5.2.1 | SC-39, SC-3 | Trust |
| Wildcard RBAC permissions | HIGH | 5.1.3 | AC-6, CM-7 | RBAC |
| Missing default-deny NetworkPolicy | HIGH | 5.3.2 | SC-7, SC-7(5) | Network |
| Root user containers | HIGH | 5.2.7 | AC-6(5) | Trust |
| Secrets in ConfigMaps | HIGH | 5.4.1 | SC-28, IA-5 | Secrets |
| No encryption at rest | HIGH | 5.4.2 | SC-28, SC-12 | Secrets |
| Token auto-mounting | MEDIUM | 5.1.6 | AC-6, IA-5 | RBAC |
| Writable root filesystem | MEDIUM | 5.2.4 | CM-6 | Trust |
| Privilege escalation allowed | MEDIUM | 5.2.5 | AC-6(10) | Trust |
| Secrets in environment variables | MEDIUM | 5.4.1 | SC-28 | Secrets |
| Missing resource limits | LOW | 5.2.9 | SC-4, CM-6 | Trust |

## Prerequisites

- Ubuntu 22.04 LTS (VirtualBox VM recommended)
- Docker 24.x+
- Minikube 1.34+ with Calico CNI
- Python 3.10+
- kubectl

## Quick Start
```bash
# 1. Clone the repository
git clone https://github.com/siddhant007/zero-trust-k8s-policy-enforcement.git
cd zero-trust-k8s-policy-enforcement

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start Minikube with Calico CNI
minikube start --driver=docker --cpus=2 --memory=4096 --cni=calico

# 5. Deploy test resources
kubectl apply -f bad-pod.yaml
kubectl apply -f good-pod.yaml
kubectl apply -f bad-rbac.yaml
kubectl apply -f secure-network-policy.yaml
kubectl apply -f test-secrets.yaml

# 6. Run the auditor
python3 main.py
```

## Sample Output
═══ ZERO TRUST COMPLIANCE SCORE ═══
████████████████░░░░░░░░░░░░░░░░░░░░░░░░  43.2%  Grade: C
Status: NEEDS IMPROVEMENT
Checks Passed: 8/20
Compliance by Category:
RBAC:     33.3%   (1/3 passed)
Network:  40.0%   (2/5 passed)
Trust:    50.0%   (3/6 passed)
Secrets:  25.0%   (1/4 passed)
═══ AUDIT SUMMARY ═══
Total violations found: 20
Total risk score: 955
Auto-remediated: 6
Pending human review: 14
Remediation manifests generated: 12
Framework Coverage:
NIST 800-53: 15 controls checked
ISO 27001:   10 controls checked
CIS Benchmark: 8 checks covered

## Project Structure
zero-trust-k8s-policy-enforcement/
├── main.py                      # Entry point — orchestrates full audit pipeline
├── config.py                    # Loads baseline.yaml and K8s API clients
├── baseline.yaml                # Formal Zero Trust policy definition
├── risk_classifier.py           # Severity scoring and violation classification
├── compliance_scorer.py         # Weighted compliance percentage calculator
├── framework_mapping.py         # NIST 800-53 and ISO 27001 control mappings
├── cis_benchmark.py             # CIS Kubernetes Benchmark mappings
├── manifest_generator.py        # YAML remediation manifest generator
├── human_review.py              # Human review queue for HIGH/CRITICAL
├── report_generator.py          # JSON + HTML dashboard report generator
├── requirements.txt             # Python dependencies
├── auditors/
│   ├── rbac_auditor.py          # RBAC violation detection
│   ├── network_auditor.py       # Network policy violation detection
│   ├── trust_auditor.py         # Workload security violation detection
│   └── secrets_auditor.py       # Secret management violation detection
├── remediation/
│   └── auto_remediator.py       # Automated fix application via K8s API
├── k8s-manifests/
│   ├── bad-pod.yaml             # Intentionally insecure test pod
│   ├── good-pod.yaml            # Properly secured test pod
│   ├── bad-rbac.yaml            # Over-permissioned RBAC binding
│   ├── secure-network-policy.yaml  # Zero Trust network policies
│   └── test-secrets.yaml        # Insecure secret test resources
├── reports/                     # Generated audit reports (gitignored)
│   └── manifests/               # Generated YAML fix files (gitignored)
└── docs/
└── research-paper.pdf       # Project research paper

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| Kubernetes Client | kubernetes-client (Python) |
| Policy Parsing | PyYAML |
| Terminal UI | Rich |
| Report Templating | Jinja2 |
| Cluster | Minikube (single-node) |
| CNI | Calico (NetworkPolicy enforcement) |
| OS | Ubuntu 22.04 LTS (VirtualBox) |

## Authors

- **Alister Rodrigues** — Pace University, MS Cybersecurity
- **Pranav Karelia** — Pace University, MS Cybersecurity
- **Siddhant Patel** — Pace University, MS Cybersecurity

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) file.
