"""
hetero_graph_builder.py
-----------------------
Builds a PyTorch Geometric HeteroData object from the IAM graph.
Each node type gets its own feature matrix.
Each (src_type, edge_type, dst_type) triplet gets its own edge_index.

Also loads CISA KEV catalog and annotates nodes with KEV scores.
"""

import json
import logging
import pickle
import re
from pathlib import Path

import pandas as pd
import requests
import torch
import yaml
from torch_geometric.data import HeteroData

from src.iam.iam_parser import IAMParser, IAMNode

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NODE_FEATURE_DIM = 8  # fixed feature vector length per node type


class HeteroGraphBuilder:
    """
    Constructs a PyG HeteroData graph with:
    - 4 node types: user, role, service, resource
    - 4 edge relation types: assume_role, grants, accesses, network_reachable
    - CISA KEV-based vulnerability annotation
    """

    def __init__(self, config_path: str):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        self.parser = IAMParser(self.config["paths"]["iam_policy_dir"])
        self.kev_data: list[dict] = []
        self.node_index: dict[str, dict[str, int]] = {}  # type -> {node_id -> local_idx}
        self.data = HeteroData()

    def build(self) -> HeteroData:
        logger.info("Parsing IAM policies...")
        nodes, edges = self.parser.parse_all()

        logger.info("Loading CISA KEV catalog...")
        self._load_kev()

        logger.info("Building node feature matrices...")
        self._build_node_features(nodes)

        logger.info("Building edge indices...")
        self._build_edge_indices(edges, nodes)

        logger.info("HeteroData built:")
        for ntype in self.data.node_types:
            logger.info("  Node type '%s': %d nodes, %d features",
                        ntype, self.data[ntype].x.shape[0], self.data[ntype].x.shape[1])
        for etype in self.data.edge_types:
            logger.info("  Edge type %s: %d edges", etype, self.data[etype].edge_index.shape[1])

        return self.data

    def save(self, output_path: str) -> None:
        with open(output_path, "wb") as f:
            pickle.dump(self.data, f)
        logger.info("HeteroData saved to %s", output_path)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _load_kev(self) -> None:
        kev_path = Path(self.config["paths"].get("cisa_kev", "data/raw/cisa_kev/kev.json"))
        if kev_path.exists():
            with open(kev_path) as f:
                raw = json.load(f)
            self.kev_data = raw.get("vulnerabilities", [])
            logger.info("Loaded %d KEV entries from disk", len(self.kev_data))
        else:
            logger.info("Fetching CISA KEV from %s", CISA_KEV_URL)
            try:
                resp = requests.get(CISA_KEV_URL, timeout=15)
                resp.raise_for_status()
                raw = resp.json()
                self.kev_data = raw.get("vulnerabilities", [])
                kev_path.parent.mkdir(parents=True, exist_ok=True)
                with open(kev_path, "w") as f:
                    json.dump(raw, f)
                logger.info("Fetched and cached %d KEV entries", len(self.kev_data))
            except Exception as e:
                logger.warning("Could not load CISA KEV: %s — using empty KEV set", e)

    def _kev_score(self, node: IAMNode) -> float:
        """Returns fraction of KEV entries that mention node's software tag."""
        software = node.tags.get("software", "").lower()
        if not software:
            return 0.0
        matches = sum(
            1 for v in self.kev_data
            if software in v.get("product", "").lower()
            or software in v.get("vendorProject", "").lower()
        )
        return min(matches / max(len(self.kev_data), 1) * 500, 1.0)  # scale to 0-1

    def _node_to_features(self, node: IAMNode) -> list[float]:
        """Convert IAMNode to fixed-length feature vector."""
        type_enc = {"user": 0, "role": 1, "service": 2, "resource": 3}
        return [
            type_enc.get(node.node_type, -1) / 3.0,          # node type (normalized)
            min(len(node.permissions) / 30.0, 1.0),           # permission count
            min(node.sensitive_count / 10.0, 1.0),            # sensitive permission count
            float(node.is_admin),                              # is admin
            node.criticality,                                  # criticality
            self._kev_score(node),                             # CISA KEV score
            0.0,                                               # placeholder: in_degree (set after graph built)
            0.0,                                               # placeholder: out_degree
        ]

    def _build_node_features(self, nodes: dict[str, IAMNode]) -> None:
        by_type = self.parser.get_nodes_by_type()

        for ntype, node_list in by_type.items():
            if not node_list:
                continue
            self.node_index[ntype] = {n.node_id: i for i, n in enumerate(node_list)}
            feats = [self._node_to_features(n) for n in node_list]
            self.data[ntype].x = torch.tensor(feats, dtype=torch.float)
            # Store node IDs for later lookup
            self.data[ntype].node_ids = [n.node_id for n in node_list]

    def _build_edge_indices(self, edges, nodes) -> None:
        """
        Build edge_index for each (src_type, edge_type, dst_type) triplet.
        PyG HeteroData requires separate edge_index per relation.
        """
        # Collect edges per relation triplet
        edge_buckets: dict[tuple, list[tuple[int, int]]] = {}

        for edge in edges:
            src_node = nodes.get(edge.source)
            dst_node = nodes.get(edge.target)
            if not src_node or not dst_node:
                continue

            src_type = src_node.node_type
            dst_type = dst_node.node_type
            etype = edge.edge_type

            if src_type not in self.node_index or dst_type not in self.node_index:
                continue

            src_idx = self.node_index[src_type].get(edge.source)
            dst_idx = self.node_index[dst_type].get(edge.target)

            if src_idx is None or dst_idx is None:
                continue

            key = (src_type, etype, dst_type)
            edge_buckets.setdefault(key, []).append((src_idx, dst_idx))

        for (src_type, etype, dst_type), edge_list in edge_buckets.items():
            src_idx, dst_idx = zip(*edge_list)
            self.data[src_type, etype, dst_type].edge_index = torch.tensor(
                [list(src_idx), list(dst_idx)], dtype=torch.long
            )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/default.yaml")
    ap.add_argument("--output", default="data/processed/hetero_graph.pkl")
    args = ap.parse_args()

    builder = HeteroGraphBuilder(args.config)
    data = builder.build()
    builder.save(args.output)
