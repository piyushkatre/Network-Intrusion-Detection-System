"""
PBFT (Practical Byzantine Fault Tolerance) consensus simulation
for the B-NIDS permissioned blockchain network.
"""

import time
import threading
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass, field


class ConsensusPhase(Enum):
    IDLE = "idle"
    PRE_PREPARE = "pre_prepare"
    PREPARE = "prepare"
    COMMIT = "commit"
    FINALIZED = "finalized"
    FAILED = "failed"


@dataclass
class ConsensusRound:
    round_id: int
    block_hash: str
    proposer: str
    phase: ConsensusPhase = ConsensusPhase.IDLE
    prepare_votes: int = 0
    commit_votes: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    finalized: bool = False

    @property
    def latency_ms(self) -> float:
        if self.end_time > 0:
            return (self.end_time - self.start_time) * 1000
        return 0.0


class PBFTConsensus:
    """
    Simulated PBFT consensus for the permissioned blockchain.

    Safety guarantee: tolerates up to f = (n-1)/3 Byzantine nodes.
    Protocol: Pre-prepare -> Prepare -> Commit (3-phase).
    """

    def __init__(self, node_ids: List[str], identity_manager=None):
        self.node_ids = list(node_ids)
        self.n = len(node_ids)
        self.f = (self.n - 1) // 3
        self.required_votes = 2 * self.f + 1
        self.identity_manager = identity_manager
        self.current_leader_index = 0
        self.round_counter = 0
        self.rounds: List[ConsensusRound] = []
        self.lock = threading.Lock()
        # Metrics
        self.total_rounds = 0
        self.successful_rounds = 0
        self.failed_rounds = 0
        self.total_latency_ms = 0.0

    @property
    def current_leader(self) -> str:
        return self.node_ids[self.current_leader_index % self.n]

    def rotate_leader(self):
        self.current_leader_index = (self.current_leader_index + 1) % self.n

    def run_consensus(self, block_hash: str, block_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute full PBFT consensus round. Returns result with latency metrics."""
        with self.lock:
            self.round_counter += 1
            round_id = self.round_counter

        cr = ConsensusRound(round_id=round_id, block_hash=block_hash,
                            proposer=self.current_leader)
        result = {
            "round_id": round_id, "proposer": self.current_leader,
            "block_hash": block_hash, "total_nodes": self.n,
            "fault_tolerance": self.f, "required_votes": self.required_votes,
            "phases": []
        }

        # Phase 1: Pre-Prepare — leader proposes
        p1_start = time.time()
        cr.phase = ConsensusPhase.PRE_PREPARE
        signature = ""
        if self.identity_manager:
            node = self.identity_manager.get_node(self.current_leader)
            if node:
                signature = node.sign(block_hash)
        p1_ms = (time.time() - p1_start) * 1000
        result["phases"].append({"name": "pre_prepare", "leader": self.current_leader,
                                  "latency_ms": round(p1_ms, 3)})

        # Phase 2: Prepare — nodes verify and vote
        p2_start = time.time()
        cr.phase = ConsensusPhase.PREPARE
        prepare_votes = 0
        for nid in self.node_ids:
            if nid == self.current_leader:
                continue
            if self._verify_block(nid, block_hash, block_data):
                prepare_votes += 1
        cr.prepare_votes = prepare_votes
        p2_ms = (time.time() - p2_start) * 1000
        prepare_ok = prepare_votes >= self.required_votes - 1
        result["phases"].append({"name": "prepare", "votes": prepare_votes,
                                  "required": self.required_votes - 1,
                                  "success": prepare_ok, "latency_ms": round(p2_ms, 3)})

        if not prepare_ok:
            cr.phase = ConsensusPhase.FAILED
            cr.end_time = time.time()
            self.failed_rounds += 1
            self.total_rounds += 1
            result["finalized"] = False
            result["status"] = "failed_prepare"
            result["total_latency_ms"] = round(cr.latency_ms, 3)
            self.rounds.append(cr)
            self.rotate_leader()
            return result

        # Phase 3: Commit — nodes commit and endorse
        p3_start = time.time()
        cr.phase = ConsensusPhase.COMMIT
        endorsements = []
        for nid in self.node_ids:
            sig, cert = "", ""
            if self.identity_manager:
                node = self.identity_manager.get_node(nid)
                if node:
                    sig = node.sign(block_hash)
                    cert = node.cert_hash
            endorsements.append({
                "node_id": nid,
                "signature": sig[:32] + "..." if len(sig) > 32 else sig,
                "cert_hash": cert[:16] + "..." if len(cert) > 16 else cert
            })
        cr.commit_votes = len(endorsements)
        p3_ms = (time.time() - p3_start) * 1000
        commit_ok = cr.commit_votes >= self.required_votes
        result["phases"].append({"name": "commit", "votes": cr.commit_votes,
                                  "required": self.required_votes,
                                  "success": commit_ok, "latency_ms": round(p3_ms, 3)})

        cr.end_time = time.time()
        if commit_ok:
            cr.phase = ConsensusPhase.FINALIZED
            cr.finalized = True
            self.successful_rounds += 1
            result["finalized"] = True
            result["status"] = "committed"
            result["endorsements"] = endorsements
        else:
            cr.phase = ConsensusPhase.FAILED
            self.failed_rounds += 1
            result["finalized"] = False
            result["status"] = "failed_commit"

        self.total_rounds += 1
        self.total_latency_ms += cr.latency_ms
        result["total_latency_ms"] = round(cr.latency_ms, 3)
        self.rounds.append(cr)
        self.rotate_leader()
        return result

    def _verify_block(self, node_id: str, block_hash: str, block_data: Dict) -> bool:
        if self.identity_manager:
            if not self.identity_manager.is_enrolled(node_id):
                return False
        if not block_hash or len(block_hash) != 64:
            return False
        required = {"index", "timestamp", "previous_hash"}
        return required.issubset(set(block_data.keys()))

    def get_metrics(self) -> Dict[str, Any]:
        avg = self.total_latency_ms / self.successful_rounds if self.successful_rounds > 0 else 0
        recent = [r.latency_ms for r in self.rounds[-50:] if r.finalized]
        return {
            "total_rounds": self.total_rounds,
            "successful_rounds": self.successful_rounds,
            "failed_rounds": self.failed_rounds,
            "success_rate_pct": round(
                self.successful_rounds / self.total_rounds * 100, 2
            ) if self.total_rounds > 0 else 0,
            "average_latency_ms": round(avg, 3),
            "min_latency_ms": round(min(recent), 3) if recent else 0,
            "max_latency_ms": round(max(recent), 3) if recent else 0,
            "total_nodes": self.n, "fault_tolerance_f": self.f,
            "quorum_size": self.required_votes, "current_leader": self.current_leader
        }
