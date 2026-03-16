"""
B-NIDS Permissioned Blockchain Module
Fabric-inspired architecture with PBFT consensus, smart contracts,
identity management, and off-chain evidence storage.
"""

from blockchain.block import Block, MerkleTree
from blockchain.identity import IdentityManager, NodeIdentity
from blockchain.consensus import PBFTConsensus
from blockchain.smart_contracts import SmartContractEngine
from blockchain.off_chain_store import OffChainStore
from blockchain.chain import PermissionedChain
from blockchain.fabric_network import FabricNetwork

__all__ = [
    "Block", "MerkleTree",
    "IdentityManager", "NodeIdentity",
    "PBFTConsensus",
    "SmartContractEngine",
    "OffChainStore",
    "PermissionedChain",
    "FabricNetwork"
]
