"""
Simulated multi-peer Fabric-inspired network for B-NIDS.
Orchestrates identity management, PBFT consensus, smart contracts,
off-chain storage, and the persistent blockchain into a unified network.
"""

import time
import json
import threading
from typing import Dict, List, Any, Optional

from blockchain.identity import IdentityManager
from blockchain.consensus import PBFTConsensus
from blockchain.smart_contracts import SmartContractEngine
from blockchain.off_chain_store import OffChainStore
from blockchain.chain import PermissionedChain


class FabricNetwork:
    """
    Fabric-inspired permissioned blockchain network.

    Integrates:
    - Identity management (certificate-based enrollment)
    - PBFT consensus (3-phase agreement)
    - Smart contracts (alert validation, reputation, escalation)
    - Off-chain evidence storage (content-addressed)
    - Persistent blockchain (SQLite-backed)
    """

    DEFAULT_ORGS = [
        {"name": "SecurityOps", "peers": ["secops-peer0", "secops-peer1"]},
        {"name": "NetworkTeam", "peers": ["netteam-peer0", "netteam-peer1"]},
        {"name": "ThreatIntel", "peers": ["threatintel-peer0"]},
    ]

    def __init__(self, organizations: List[Dict] = None,
                 difficulty: int = 2, db_path: str = None,
                 storage_dir: str = None):
        self.identity_mgr = IdentityManager()
        self.contract_engine = SmartContractEngine()
        self.off_chain = OffChainStore(storage_dir)
        self.chain = PermissionedChain(db_path, difficulty)
        self.lock = threading.Lock()
        self.network_start_time = time.time()

        # Metrics
        self.total_alerts_processed = 0
        self.total_alerts_committed = 0
        self.processing_times: List[float] = []

        # Initialize network with organizations and peers
        orgs = organizations or self.DEFAULT_ORGS
        all_peer_ids = []
        for org in orgs:
            for peer_id in org["peers"]:
                self.identity_mgr.register_node(peer_id, org["name"], "peer")
                self.contract_engine.reputation.execute(
                    "register_node", {"node_id": peer_id}
                )
                all_peer_ids.append(peer_id)

        # Initialize consensus with all enrolled peers
        self.consensus = PBFTConsensus(all_peer_ids, self.identity_mgr)

    def process_threat(self, alert_data: Dict[str, Any],
                       submitter: str = None) -> Dict[str, Any]:
        """
        Full pipeline for processing an intrusion alert:
        1. Smart contract validation & escalation
        2. Off-chain evidence storage
        3. PBFT consensus
        4. Blockchain commitment

        Returns comprehensive result with metrics from each stage.
        """
        start = time.time()
        if submitter is None:
            enrolled = self.identity_mgr.get_enrolled_nodes()
            submitter = enrolled[0] if enrolled else "unknown"

        result = {"submitter": submitter, "timestamp": time.time(), "stages": {}}

        # Stage 1: Smart Contract Processing
        sc_result = self.contract_engine.process_alert(alert_data, submitter)
        result["stages"]["smart_contracts"] = {
            "accepted": sc_result.get("accepted", False),
            "validation": sc_result.get("validation", {}),
            "escalation": sc_result.get("escalation", {}),
            "reputation_update": sc_result.get("reputation_update"),
            "processing_time_ms": sc_result.get("total_processing_time_ms", 0)
        }

        if not sc_result.get("accepted", False):
            result["committed"] = False
            result["reason"] = "Smart contract validation failed"
            result["total_time_ms"] = round((time.time() - start) * 1000, 3)
            with self.lock:
                self.total_alerts_processed += 1
            return result

        # Stage 2: Off-chain evidence storage
        evidence = self.off_chain.store(
            alert_data, category="intrusion_alert", submitter=submitter
        )
        result["stages"]["off_chain_storage"] = {
            "content_hash": evidence["content_hash"],
            "size_bytes": evidence["size_bytes"],
            "storage_time_ms": evidence["storage_time_ms"]
        }

        # Stage 3: Build on-chain transaction (hash reference only)
        on_chain_tx = {
            "alert_type": alert_data.get("alert_type", "unknown"),
            "severity": alert_data.get("severity", 0),
            "confidence": alert_data.get("confidence", 0),
            "source_ip": alert_data.get("source_ip", "unknown"),
            "timestamp": alert_data.get("timestamp", time.time()),
            "evidence_hash": evidence["content_hash"],
            "submitter": submitter,
            "validation_digest": sc_result.get("validation", {}).get(
                "evidence_digest", ""
            ),
        }

        # Stage 4: PBFT Consensus
        # We need a preliminary block hash for consensus
        import hashlib
        preliminary_hash = hashlib.sha256(
            json.dumps(on_chain_tx, sort_keys=True, default=str).encode()
        ).hexdigest()

        consensus_result = self.consensus.run_consensus(
            preliminary_hash,
            {"index": 0, "timestamp": time.time(),
             "previous_hash": "pending", "transactions": [on_chain_tx]}
        )
        result["stages"]["consensus"] = {
            "finalized": consensus_result.get("finalized", False),
            "round_id": consensus_result.get("round_id"),
            "total_latency_ms": consensus_result.get("total_latency_ms", 0),
            "phases": consensus_result.get("phases", []),
            "endorsements_count": len(consensus_result.get("endorsements", []))
        }

        if not consensus_result.get("finalized", False):
            result["committed"] = False
            result["reason"] = "Consensus failed"
            result["total_time_ms"] = round((time.time() - start) * 1000, 3)
            with self.lock:
                self.total_alerts_processed += 1
            return result

        # Stage 5: Commit to chain
        block_result = self.chain.add_block(
            [on_chain_tx], proposer_id=consensus_result.get("proposer", submitter),
            endorsements=consensus_result.get("endorsements", [])
        )
        result["stages"]["blockchain"] = {
            "block_index": block_result["block_index"],
            "block_hash": block_result["block_hash"],
            "merkle_root": block_result["merkle_root"],
            "mining_time_ms": block_result["mining_time_ms"]
        }

        result["committed"] = True
        total_ms = (time.time() - start) * 1000
        result["total_time_ms"] = round(total_ms, 3)

        with self.lock:
            self.total_alerts_processed += 1
            self.total_alerts_committed += 1
            self.processing_times.append(total_ms)
            if len(self.processing_times) > 1000:
                self.processing_times = self.processing_times[-500:]

        # Update reputation for successful commitment
        self.contract_engine.reputation.execute(
            "update_reputation",
            {"node_id": submitter, "event_type": "consensus_participation"}
        )

        return result

    def verify_chain(self) -> Dict[str, Any]:
        """Full blockchain integrity verification."""
        return self.chain.validate_chain()

    def forensic_search(self, **kwargs) -> List[Dict[str, Any]]:
        """Search committed transactions for forensic analysis."""
        return self.chain.search_transactions(**kwargs)

    def retrieve_evidence(self, content_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve off-chain evidence by content hash."""
        return self.off_chain.retrieve(content_hash)

    def verify_evidence(self, content_hash: str) -> Dict[str, Any]:
        """Verify integrity of off-chain evidence."""
        return self.off_chain.verify(content_hash)

    def get_network_stats(self) -> Dict[str, Any]:
        """Comprehensive network statistics for paper metrics."""
        with self.lock:
            times = self.processing_times
            avg_time = sum(times) / len(times) if times else 0
            throughput = (self.total_alerts_committed /
                          (time.time() - self.network_start_time))

        return {
            "network": {
                "uptime_seconds": round(time.time() - self.network_start_time, 1),
                "identity": self.identity_mgr.get_network_info(),
            },
            "processing": {
                "total_processed": self.total_alerts_processed,
                "total_committed": self.total_alerts_committed,
                "commit_rate_pct": round(
                    self.total_alerts_committed / self.total_alerts_processed * 100, 2
                ) if self.total_alerts_processed > 0 else 0,
                "avg_processing_time_ms": round(avg_time, 3),
                "min_processing_time_ms": round(min(times), 3) if times else 0,
                "max_processing_time_ms": round(max(times), 3) if times else 0,
                "throughput_per_sec": round(throughput, 3),
            },
            "consensus": self.consensus.get_metrics(),
            "blockchain": self.chain.get_metrics(),
            "smart_contracts": self.contract_engine.get_engine_stats(),
            "off_chain_storage": self.off_chain.get_stats(),
        }

    def get_chain_data(self) -> List[Dict[str, Any]]:
        """Get full blockchain data (backward compatible)."""
        return self.chain.get_chain_data()
