"""
Off-chain evidence storage for B-NIDS.
Content-addressed storage (IPFS-like) for large artifacts.
Only hash references are stored on the blockchain.
"""

import hashlib
import json
import os
import time
import threading
from typing import Dict, Any, Optional, List
from pathlib import Path


class OffChainStore:
    """
    Content-addressed off-chain storage.
    Stores large evidence artifacts (packet captures, feature vectors,
    model outputs) off-chain with SHA-256 content addressing.
    """

    def __init__(self, storage_dir: str = None):
        if storage_dir is None:
            storage_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "offchain_store"
            )
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.storage_dir / "index.json"
        self.index: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self._load_index()
        self.total_stored = len(self.index)
        self.total_retrieved = 0
        self.total_bytes = sum(v.get("size_bytes", 0) for v in self.index.values())

    def _load_index(self):
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    self.index = json.load(f).get("index", {})
            except (json.JSONDecodeError, IOError):
                self.index = {}

    def _save_index(self):
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump({
                    "index": self.index, "total_stored": self.total_stored,
                    "total_bytes": self.total_bytes, "last_updated": time.time()
                }, f, indent=2, default=str)
        except IOError:
            pass

    def store(self, data: Dict[str, Any], category: str = "evidence",
              submitter: str = "system") -> Dict[str, Any]:
        """
        Store data off-chain and return content hash for on-chain reference.

        Returns dict with content_hash, size, and timing metrics.
        """
        start = time.time()
        serialized = json.dumps(data, sort_keys=True, default=str)
        data_bytes = serialized.encode('utf-8')
        content_hash = hashlib.sha256(data_bytes).hexdigest()

        # IPFS-like 2-level directory structure
        dir_prefix = content_hash[:4]
        store_dir = self.storage_dir / category / dir_prefix
        store_dir.mkdir(parents=True, exist_ok=True)
        file_path = store_dir / f"{content_hash}.json"

        with self.lock:
            with open(file_path, 'w') as f:
                json.dump({
                    "content_hash": content_hash, "data": data,
                    "metadata": {
                        "category": category, "submitter": submitter,
                        "timestamp": time.time(), "size_bytes": len(data_bytes)
                    }
                }, f, indent=2, default=str)

            self.index[content_hash] = {
                "category": category, "submitter": submitter,
                "timestamp": time.time(), "size_bytes": len(data_bytes),
                "path": str(file_path.relative_to(self.storage_dir))
            }
            self.total_stored += 1
            self.total_bytes += len(data_bytes)
            self._save_index()

        elapsed = (time.time() - start) * 1000
        return {
            "content_hash": content_hash, "category": category,
            "size_bytes": len(data_bytes), "storage_time_ms": round(elapsed, 3),
            "on_chain_reference": {
                "hash": content_hash, "category": category,
                "size": len(data_bytes), "timestamp": time.time()
            }
        }

    def retrieve(self, content_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve data by content hash. Returns None if not found."""
        start = time.time()
        with self.lock:
            if content_hash not in self.index:
                return None
            meta = self.index[content_hash]

        file_path = self.storage_dir / meta["path"]
        if not file_path.exists():
            return None

        try:
            with open(file_path, 'r') as f:
                stored = json.load(f)
            self.total_retrieved += 1
            elapsed = (time.time() - start) * 1000
            return {
                "content_hash": content_hash,
                "data": stored.get("data"),
                "metadata": stored.get("metadata"),
                "retrieval_time_ms": round(elapsed, 3),
                "verified": hashlib.sha256(
                    json.dumps(stored.get("data"), sort_keys=True, default=str).encode()
                ).hexdigest() == content_hash
            }
        except (json.JSONDecodeError, IOError):
            return None

    def verify(self, content_hash: str) -> Dict[str, Any]:
        """Verify integrity of stored evidence by recomputing hash."""
        result = self.retrieve(content_hash)
        if result is None:
            return {"content_hash": content_hash, "exists": False, "valid": False}
        return {
            "content_hash": content_hash, "exists": True,
            "valid": result.get("verified", False),
            "retrieval_time_ms": result.get("retrieval_time_ms", 0)
        }

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            categories = {}
            for v in self.index.values():
                cat = v.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1
        return {
            "total_stored": self.total_stored,
            "total_retrieved": self.total_retrieved,
            "total_bytes": self.total_bytes,
            "total_mb": round(self.total_bytes / (1024 * 1024), 2),
            "categories": categories,
            "storage_dir": str(self.storage_dir)
        }
