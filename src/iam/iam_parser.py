"""
iam_parser.py
-------------
Parses IAM policy JSON files and builds a typed node/edge registry
for heterogeneous graph construction.

Node types : user | role | service | resource
Edge types : assume_role | grants | accesses | network_reachable
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

NODE_TYPES = {"user", "role", "service", "resource"}
EDGE_TYPES = {"assume_role", "grants", "accesses", "network_reachable"}

SENSITIVE_ACTIONS = {
    "iam:PassRole", "iam:CreateRole", "iam:AttachRolePolicy",
    "sts:AssumeRole", "ec2:RunInstances", "s3:GetObject",
    "secretsmanager:GetSecretValue", "lambda:InvokeFunction",
    "iam:PutRolePolicy", "iam:CreateAccessKey", "iam:CreateUser",
}


@dataclass
class IAMNode:
    node_id: str
    node_type: str
    permissions: list
    criticality: float
    tags: dict = field(default_factory=dict)

    @property
    def sensitive_count(self) -> int:
        return len(set(self.permissions) & SENSITIVE_ACTIONS)

    @property
    def is_admin(self) -> bool:
        return "*" in self.permissions or "iam:*" in self.permissions


@dataclass
class IAMEdge:
    source: str
    target: str
    edge_type: str
    conditions: dict = field(default_factory=dict)


class IAMParser:
    """Parses IAM JSON files into typed node/edge lists for HeteroGraph."""

    def __init__(self, policy_dir: str):
        self.policy_dir = Path(policy_dir)
        self.nodes: dict[str, IAMNode] = {}
        self.edges: list[IAMEdge] = []

    def parse_all(self) -> tuple[dict, list]:
        for f in self.policy_dir.glob("*.json"):
            logger.info("Parsing %s", f.name)
            self._parse_file(f)
        logger.info("Parsed %d nodes, %d edges", len(self.nodes), len(self.edges))
        return self.nodes, self.edges

    def get_nodes_by_type(self) -> dict[str, list[IAMNode]]:
        result = {t: [] for t in NODE_TYPES}
        for node in self.nodes.values():
            if node.node_type in result:
                result[node.node_type].append(node)
        return result

    def get_edges_by_type(self) -> dict[str, list[IAMEdge]]:
        result = {t: [] for t in EDGE_TYPES}
        for edge in self.edges:
            if edge.edge_type in result:
                result[edge.edge_type].append(edge)
        return result

    def _parse_file(self, filepath: Path) -> None:
        with open(filepath) as f:
            data = json.load(f)

        for p in data.get("principals", []):
            node = IAMNode(
                node_id=p["id"],
                node_type=p.get("type", "role"),
                permissions=p.get("permissions", []),
                criticality=p.get("criticality", 0.5),
                tags=p.get("tags", {}),
            )
            self.nodes[node.node_id] = node

        for t in data.get("trust_relationships", []):
            self.edges.append(IAMEdge(
                source=t["principal"],
                target=t["target"],
                edge_type=t.get("type", "assume_role"),
                conditions=t.get("conditions", {}),
            ))


if __name__ == "__main__":
    parser = IAMParser("data/raw/iam")
    nodes, edges = parser.parse_all()
    by_type = parser.get_nodes_by_type()
    for t, ns in by_type.items():
        print(f"  {t}: {len(ns)} nodes")
