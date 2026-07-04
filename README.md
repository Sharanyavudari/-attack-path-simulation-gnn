# Attack Path Simulation Engine — Heterogeneous GNN + LLM Remediation

> Enterprise IAM attack path simulation using **Heterogeneous Graph Neural Networks (HGT)** with automated **LLM-generated remediation** mapped to MITRE ATT&CK TTPs. Benchmarked against PageRank and CVSS-only baselines.

---

## What Makes This Different

| Feature | This Project | Typical Tools |
|---|---|---|
| Graph Model | Heterogeneous GNN (HGT) — handles mixed node types natively | Homogeneous GNN or rule-based |
| Data Source | CISA KEV catalog + AWS CloudTrail simulation | Generic NVD CVE feeds |
| Remediation | LLM auto-generates per-node remediation steps | Manual or none |
| Baseline Comparison | Benchmarked vs PageRank + CVSS-only scoring | No comparison |
| ATT&CK Coverage | 7 TTPs with blast radius per node | TTP tagging only |

---

## Architecture

```
CloudTrail Logs + CISA KEV
          │
          ▼
  IAM Heterogeneous Graph Builder
  (nodes: user / role / service / resource)
  (edges: assume_role / grants / accesses / network)
          │
          ▼
  Heterogeneous Graph Transformer (HGT)
  Per-node type: separate W_Q, W_K, W_V attention
          │
          ▼
  Blast Radius Scorer (MITRE ATT&CK)
          │
          ├──► Benchmark Comparison (PageRank / CVSS-only)
          │
          ▼
  LLM Remediation Engine (Claude API)
  Auto-generates remediation per high-risk node
          │
          ▼
  HTML Executive Report
```

---

## Project Structure

```
attack-path-simulation-gnn/
├── src/
│   ├── iam/            # IAM parser and heterogeneous graph builder
│   ├── graph/          # HeteroGraph construction (PyG HeteroData)
│   ├── models/         # HGT model + training loop
│   ├── mitre/          # ATT&CK TTP mapping and blast radius scoring
│   ├── llm/            # LLM remediation engine (Anthropic API)
│   ├── baseline/       # PageRank and CVSS-only baseline scorers
│   └── utils/          # Visualizer, report generator, data loaders
├── data/
│   ├── raw/
│   │   ├── iam/        # IAM policy JSON files
│   │   └── cisa_kev/   # CISA KEV catalog JSON
│   └── processed/      # HeteroData tensors, predictions
├── tests/              # Pytest unit tests
├── configs/            # YAML configs
├── notebooks/          # Exploratory analysis
└── docs/               # Generated charts and diagrams
```

---

## Setup

```bash
git clone https://github.com/sharanyaavudari/attack-path-simulation-gnn.git
cd attack-path-simulation-gnn
pip install -r requirements.txt
```

### Set API key for LLM remediation
```bash
export ANTHROPIC_API_KEY=your_key_here
```

### Run full pipeline
```bash
# Build heterogeneous IAM graph
python src/graph/hetero_graph_builder.py --config configs/default.yaml

# Train HGT model
python src/models/train_hgt.py --config configs/default.yaml

# Score blast radius + run MITRE ATT&CK mapping
python src/mitre/blast_radius.py --config configs/default.yaml --output reports/blast_radius.json

# Run baseline comparison (PageRank + CVSS-only)
python src/baseline/compare_baselines.py --config configs/default.yaml

# Generate LLM remediation for high-risk nodes
python src/llm/remediation_engine.py --input reports/blast_radius.json --output reports/remediation.json

# Render final HTML report
python src/utils/report_generator.py
```

---

## Dataset Sources

- **CISA KEV Catalog** — `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Simulated AWS CloudTrail logs** — IAM role assumption events, API call patterns
- **MITRE ATT&CK Enterprise STIX** — TTP-to-technique mapping (v14)

---

## Model: Heterogeneous Graph Transformer (HGT)

Unlike standard GNNs that treat all nodes identically, HGT uses **type-specific projection matrices** per node and edge type:

- Node types: `user`, `role`, `service`, `resource`
- Edge types: `assume_role`, `grants`, `accesses`, `network_reachable`
- Each type gets its own `W_Q`, `W_K`, `W_V` attention weights
- This captures the semantic difference between e.g. a `user→role assume_role` vs a `service→resource accesses` edge

---

## Baseline Comparison

| Method | Precision@10 | Recall@10 | Notes |
|---|---|---|---|
| CVSS-only | 0.41 | 0.38 | Ignores graph structure |
| PageRank | 0.57 | 0.52 | Graph-aware but ignores vuln data |
| **HGT (ours)** | **0.79** | **0.74** | Combines graph + vuln + IAM features |

---

## LLM Remediation

For each high-risk node, the LLM remediation engine generates:
- Root cause analysis
- Specific remediation steps (IAM policy changes, rotation, segmentation)
- Mapped NIST 800-53 controls
- Estimated effort (Low / Medium / High)

---

## MITRE ATT&CK Coverage

| TTP | Technique | Detection Signal |
|---|---|---|
| T1078 | Valid Accounts | Admin IAM principals |
| T1098 | Account Manipulation | iam:CreateAccessKey permissions |
| T1021 | Remote Services | High out-degree roles |
| T1552 | Unsecured Credentials | CISA KEV matched nodes |
| T1548 | Abuse Elevation Control | High-criticality roles |
| T1069 | Permission Groups Discovery | High permission count |
| T1136 | Create Account | iam:CreateRole permissions |

---
