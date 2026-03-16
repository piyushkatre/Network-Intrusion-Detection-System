"""
Enhanced Block structure for B-NIDS permissioned blockchain.
Includes Merkle tree computation, digital signature support,
and block endorsement tracking.
"""

import hashlib
import json
import time
from typing import List, Dict, Any, Optional


class MerkleTree:
    """Merkle Tree for transaction integrity verification."""

    @staticmethod
    def hash_data(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def compute_root(transactions: List[Dict[str, Any]]) -> str:
        if not transactions:
            return hashlib.sha256(b"empty_tree").hexdigest()
        leaves = [
            MerkleTree.hash_data(json.dumps(tx, sort_keys=True, default=str))
            for tx in transactions
        ]
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            next_level = []
            for i in range(0, len(leaves), 2):
                combined = leaves[i] + leaves[i + 1]
                next_level.append(MerkleTree.hash_data(combined))
            leaves = next_level
        return leaves[0]

    @staticmethod
    def get_proof(transactions: List[Dict[str, Any]], index: int) -> List[Dict[str, str]]:
        """Get Merkle proof for a transaction at given index."""
        if not transactions or index >= len(transactions):
            return []
        leaves = [
            MerkleTree.hash_data(json.dumps(tx, sort_keys=True, default=str))
            for tx in transactions
        ]
        proof = []
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            sibling_index = index ^ 1
            if sibling_index < len(leaves):
                proof.append({
                    "hash": leaves[sibling_index],
                    "position": "right" if index % 2 == 0 else "left"
                })
            next_level = []
            for i in range(0, len(leaves), 2):
                combined = leaves[i] + leaves[i + 1]
                next_level.append(MerkleTree.hash_data(combined))
            leaves = next_level
            index //= 2
        return proof


class Block:
    """Enhanced block with Merkle root, proposer identity, and endorsements."""

    def __init__(self, index: int, timestamp: float,
                 transactions: List[Dict[str, Any]], previous_hash: str,
                 proposer_id: str = "genesis",
                 endorsements: Optional[List[Dict[str, Any]]] = None,
                 block_type: str = "standard"):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.proposer_id = proposer_id
        self.endorsements = endorsements or []
        self.block_type = block_type
        self.merkle_root = MerkleTree.compute_root(transactions)
        self.nonce = 0
        self.hash = self.calculate_hash()
        self.creation_time = 0.0

    def calculate_hash(self) -> str:
        block_header = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "proposer_id": self.proposer_id,
            "block_type": self.block_type,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_header.encode('utf-8')).hexdigest()

    def mine_block(self, difficulty: int) -> float:
        """Mine block with PoW. Returns time taken in seconds."""
        start_time = time.time()
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        self.creation_time = time.time() - start_time
        return self.creation_time

    def add_endorsement(self, node_id: str, signature: str, cert_hash: str = ""):
        self.endorsements.append({
            "node_id": node_id, "signature": signature,
            "cert_hash": cert_hash, "timestamp": time.time()
        })

    def has_sufficient_endorsements(self, required: int) -> bool:
        return len(self.endorsements) >= required

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index, "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash, "hash": self.hash,
            "merkle_root": self.merkle_root, "proposer_id": self.proposer_id,
            "endorsements": self.endorsements, "block_type": self.block_type,
            "nonce": self.nonce, "creation_time": self.creation_time,
            "tx_count": len(self.transactions)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        block = cls(
            index=data["index"], timestamp=data["timestamp"],
            transactions=data["transactions"],
            previous_hash=data["previous_hash"],
            proposer_id=data.get("proposer_id", "genesis"),
            endorsements=data.get("endorsements", []),
            block_type=data.get("block_type", "standard")
        )
        block.nonce = data.get("nonce", 0)
        block.hash = data.get("hash", block.calculate_hash())
        block.merkle_root = data.get("merkle_root",
                                     MerkleTree.compute_root(data["transactions"]))
        block.creation_time = data.get("creation_time", 0.0)
        return block
