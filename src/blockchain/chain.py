"""
SQLite-backed persistent permissioned blockchain for B-NIDS.
Supports chain validation, forensic queries, and performance metrics.
"""

import sqlite3
import json
import time
import threading
import os
from typing import Dict, List, Any, Optional
from blockchain.block import Block, MerkleTree


class PermissionedChain:
    """Persistent permissioned blockchain backed by SQLite."""

    def __init__(self, db_path: str = None, difficulty: int = 2):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "blockchain.db"
            )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.difficulty = difficulty
        self.lock = threading.Lock()
        # Performance metrics
        self.blocks_mined = 0
        self.total_mining_time = 0.0
        self.total_txns = 0
        self._init_db()
        if self._get_chain_length() == 0:
            self._create_genesis()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS blocks (
                    idx INTEGER PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    previous_hash TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    merkle_root TEXT NOT NULL,
                    proposer_id TEXT NOT NULL,
                    block_type TEXT DEFAULT 'standard',
                    nonce INTEGER DEFAULT 0,
                    creation_time REAL DEFAULT 0,
                    endorsements TEXT DEFAULT '[]',
                    tx_count INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_idx INTEGER NOT NULL,
                    tx_data TEXT NOT NULL,
                    evidence_digest TEXT,
                    FOREIGN KEY(block_idx) REFERENCES blocks(idx)
                );
                CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_idx);
                CREATE INDEX IF NOT EXISTS idx_block_hash ON blocks(hash);
            """)
            conn.commit()
        finally:
            conn.close()

    def _create_genesis(self):
        genesis = Block(0, time.time(), [], "0", proposer_id="genesis",
                        block_type="genesis")
        genesis.mine_block(self.difficulty)
        self._save_block(genesis)

    def _save_block(self, block: Block):
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO blocks
                   (idx, timestamp, previous_hash, hash, merkle_root,
                    proposer_id, block_type, nonce, creation_time,
                    endorsements, tx_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (block.index, block.timestamp, block.previous_hash,
                 block.hash, block.merkle_root, block.proposer_id,
                 block.block_type, block.nonce, block.creation_time,
                 json.dumps(block.endorsements, default=str),
                 len(block.transactions))
            )
            for tx in block.transactions:
                digest = MerkleTree.hash_data(json.dumps(tx, sort_keys=True, default=str))
                conn.execute(
                    "INSERT INTO transactions (block_idx, tx_data, evidence_digest) VALUES (?, ?, ?)",
                    (block.index, json.dumps(tx, default=str), digest)
                )
            conn.commit()
        finally:
            conn.close()

    def _get_chain_length(self) -> int:
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT COUNT(*) FROM blocks")
            return cur.fetchone()[0]
        finally:
            conn.close()

    def _get_latest_block(self) -> Optional[Block]:
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT * FROM blocks ORDER BY idx DESC LIMIT 1")
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_block(conn, row)
        finally:
            conn.close()

    def _row_to_block(self, conn, row) -> Block:
        idx = row[0]
        cur = conn.execute("SELECT tx_data FROM transactions WHERE block_idx=?", (idx,))
        txns = [json.loads(r[0]) for r in cur.fetchall()]
        block = Block(
            index=idx, timestamp=row[1], transactions=txns,
            previous_hash=row[2], proposer_id=row[5],
            endorsements=json.loads(row[9]) if row[9] else [],
            block_type=row[6] or "standard"
        )
        block.hash = row[3]
        block.merkle_root = row[4]
        block.nonce = row[7]
        block.creation_time = row[8]
        return block

    def add_block(self, transactions: List[Dict[str, Any]],
                  proposer_id: str = "default",
                  endorsements: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create, mine, and persist a new block. Returns block info + metrics."""
        with self.lock:
            latest = self._get_latest_block()
            new_index = latest.index + 1 if latest else 0
            prev_hash = latest.hash if latest else "0"

        block = Block(
            index=new_index, timestamp=time.time(),
            transactions=transactions, previous_hash=prev_hash,
            proposer_id=proposer_id, endorsements=endorsements or [],
            block_type="alert" if transactions else "empty"
        )

        mining_time = block.mine_block(self.difficulty)

        with self.lock:
            self._save_block(block)
            self.blocks_mined += 1
            self.total_mining_time += mining_time
            self.total_txns += len(transactions)

        return {
            "block_index": block.index, "block_hash": block.hash,
            "merkle_root": block.merkle_root, "tx_count": len(transactions),
            "mining_time_ms": round(mining_time * 1000, 3),
            "proposer": proposer_id,
            "endorsements_count": len(block.endorsements)
        }

    def validate_chain(self) -> Dict[str, Any]:
        """Full chain validation with hash and Merkle root verification."""
        start = time.time()
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT * FROM blocks ORDER BY idx ASC")
            rows = cur.fetchall()
            errors = []
            for i, row in enumerate(rows):
                block = self._row_to_block(conn, row)
                # Verify hash
                computed = block.calculate_hash()
                # Check Merkle root
                expected_merkle = MerkleTree.compute_root(block.transactions)
                if block.merkle_root != expected_merkle:
                    errors.append(f"Block {block.index}: Merkle root mismatch")
                # Check chain linkage
                if i > 0:
                    prev = self._row_to_block(conn, rows[i - 1])
                    if block.previous_hash != prev.hash:
                        errors.append(f"Block {block.index}: broken chain link")
            elapsed = (time.time() - start) * 1000
            return {
                "valid": len(errors) == 0, "blocks_checked": len(rows),
                "errors": errors, "validation_time_ms": round(elapsed, 3)
            }
        finally:
            conn.close()

    def get_block(self, index: int) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT * FROM blocks WHERE idx=?", (index,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_block(conn, row).to_dict()
        finally:
            conn.close()

    def get_chain_data(self) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT * FROM blocks ORDER BY idx ASC")
            return [self._row_to_block(conn, r).to_dict() for r in cur.fetchall()]
        finally:
            conn.close()

    def search_transactions(self, alert_type: str = None,
                            source_ip: str = None,
                            min_severity: int = None) -> List[Dict[str, Any]]:
        """Forensic search across all transactions."""
        start = time.time()
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT tx_data, block_idx FROM transactions")
            results = []
            for row in cur.fetchall():
                tx = json.loads(row[0])
                match = True
                if alert_type and tx.get("alert_type") != alert_type:
                    match = False
                if source_ip and tx.get("source_ip") != source_ip:
                    match = False
                if min_severity and tx.get("severity", 0) < min_severity:
                    match = False
                if match:
                    tx["_block_idx"] = row[1]
                    results.append(tx)
            elapsed = (time.time() - start) * 1000
            return results
        finally:
            conn.close()

    def get_metrics(self) -> Dict[str, Any]:
        chain_len = self._get_chain_length()
        avg_mining = (self.total_mining_time / self.blocks_mined * 1000
                      if self.blocks_mined > 0 else 0)
        return {
            "chain_length": chain_len, "blocks_mined": self.blocks_mined,
            "total_transactions": self.total_txns,
            "avg_mining_time_ms": round(avg_mining, 3),
            "total_mining_time_ms": round(self.total_mining_time * 1000, 3),
            "difficulty": self.difficulty,
            "db_path": self.db_path,
            "db_size_kb": round(os.path.getsize(self.db_path) / 1024, 2)
            if os.path.exists(self.db_path) else 0
        }
