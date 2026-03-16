"""
Enhanced BlockchainLogger for B-NIDS.
Wraps the FabricNetwork to provide backward-compatible API
while using the full permissioned blockchain infrastructure.
"""

import time
import threading
from typing import Dict, List, Any
from blockchain.fabric_network import FabricNetwork


class BlockchainLogger:
    """
    Backward-compatible wrapper around FabricNetwork.
    Preserves the same add_transaction / is_chain_valid / get_chain_data API
    used by app.py while leveraging the full permissioned blockchain.
    """

    def __init__(self, difficulty: int = 2):
        self.difficulty = difficulty
        self.network = FabricNetwork(difficulty=difficulty)
        self.lock = threading.Lock()

    def add_transaction(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process and commit a threat alert through the full pipeline:
        smart contract validation -> off-chain storage -> PBFT consensus -> blockchain.

        Returns the pipeline result with metrics.
        """
        # Ensure required fields for smart contract validation
        enriched = dict(transaction)
        enriched.setdefault("alert_type", enriched.get("prediction", "unknown"))
        enriched.setdefault("severity", self._compute_severity(enriched))
        enriched.setdefault("confidence", enriched.get("confidence", 0.5))
        enriched.setdefault("source_ip", enriched.get("source_ip", "0.0.0.0"))
        enriched.setdefault("timestamp", time.time())

        return self.network.process_threat(enriched)

    def is_chain_valid(self) -> bool:
        result = self.network.verify_chain()
        return result.get("valid", False)

    def get_chain_data(self) -> List[Dict[str, Any]]:
        return self.network.get_chain_data()

    def get_network_stats(self) -> Dict[str, Any]:
        return self.network.get_network_stats()

    def verify_evidence(self, content_hash: str) -> Dict[str, Any]:
        return self.network.verify_evidence(content_hash)

    def retrieve_evidence(self, content_hash: str):
        return self.network.retrieve_evidence(content_hash)

    def forensic_search(self, **kwargs):
        return self.network.forensic_search(**kwargs)

    def _compute_severity(self, tx: Dict[str, Any]) -> int:
        """Map prediction labels to severity levels."""
        prediction = str(tx.get("prediction", "")).upper()
        severity_map = {
            "BENIGN": 1, "NORMAL": 1,
            "PORTSCAN": 2, "PROBE": 2,
            "BRUTEFORCE": 3, "R2L": 3, "U2R": 3,
            "INFILTRATION": 3, "WEBATTACK": 3,
            "DOS": 4, "DDOS": 5, "BOTNET": 5,
        }
        for key, sev in severity_map.items():
            if key in prediction:
                return sev
        return 3  # Default medium severity
