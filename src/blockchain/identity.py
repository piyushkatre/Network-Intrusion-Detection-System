"""
Identity and enrollment management for the permissioned blockchain.
Provides certificate-based node identities with RSA key pairs and X.509 certificates.
"""

import hashlib
import hmac as hmac_module
import json
import os
import time
import threading
from typing import Dict, Optional, List

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import (
        CertificateBuilder, NameAttribute, BasicConstraints,
        random_serial_number
    )
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509 as x509_module
    import datetime
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class NodeIdentity:
    """Represents a node's identity in the permissioned network."""

    def __init__(self, node_id: str, organization: str, role: str = "peer"):
        self.node_id = node_id
        self.organization = organization
        self.role = role
        self.enrolled = False
        self.enrollment_time = None
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.cert_hash = ""
        self.reputation_score = 100.0
        self._secret_key = os.urandom(32)

    def enroll(self):
        """Generate key pair and self-signed certificate."""
        if HAS_CRYPTO:
            self._enroll_crypto()
        else:
            self._enroll_basic()
        self.enrolled = True
        self.enrollment_time = time.time()

    def _enroll_crypto(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        subject = issuer = x509_module.Name([
            NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
            NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
            NameAttribute(NameOID.COMMON_NAME, self.node_id),
        ])
        cert = (CertificateBuilder()
                .subject_name(subject).issuer_name(issuer)
                .public_key(self.public_key)
                .serial_number(random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(self.private_key, hashes.SHA256(), default_backend()))
        self.certificate = cert
        self.cert_hash = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()

    def _enroll_basic(self):
        self._secret_key = os.urandom(32)
        self.cert_hash = hashlib.sha256(
            f"{self.node_id}:{self.organization}:{time.time()}".encode()
        ).hexdigest()

    def sign(self, data: str) -> str:
        if not self.enrolled:
            raise ValueError(f"Node {self.node_id} is not enrolled")
        if HAS_CRYPTO and self.private_key:
            sig = self.private_key.sign(
                data.encode('utf-8'),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                             salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return sig.hex()
        return hmac_module.new(
            self._secret_key, data.encode('utf-8'), hashlib.sha256
        ).hexdigest()

    def verify(self, data: str, signature: str) -> bool:
        if not self.enrolled:
            return False
        if HAS_CRYPTO and self.public_key:
            try:
                self.public_key.verify(
                    bytes.fromhex(signature), data.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                 salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                return True
            except Exception:
                return False
        expected = hmac_module.new(
            self._secret_key, data.encode('utf-8'), hashlib.sha256
        ).hexdigest()
        return hmac_module.compare_digest(expected, signature)

    def to_dict(self) -> Dict:
        return {
            "node_id": self.node_id, "organization": self.organization,
            "role": self.role, "enrolled": self.enrolled,
            "enrollment_time": self.enrollment_time,
            "cert_hash": self.cert_hash, "reputation_score": self.reputation_score,
            "has_crypto": HAS_CRYPTO and self.private_key is not None
        }


class IdentityManager:
    """Manages node identities and enrollment (simplified Certificate Authority)."""

    def __init__(self):
        self.nodes: Dict[str, NodeIdentity] = {}
        self.revoked: Dict[str, float] = {}
        self.lock = threading.Lock()

    def register_node(self, node_id: str, organization: str,
                      role: str = "peer") -> NodeIdentity:
        with self.lock:
            if node_id in self.nodes:
                return self.nodes[node_id]
            if node_id in self.revoked:
                raise ValueError(f"Node {node_id} has been revoked")
            identity = NodeIdentity(node_id, organization, role)
            identity.enroll()
            self.nodes[node_id] = identity
            return identity

    def revoke_node(self, node_id: str) -> bool:
        with self.lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                self.revoked[node_id] = time.time()
                return True
            return False

    def get_node(self, node_id: str) -> Optional[NodeIdentity]:
        return self.nodes.get(node_id)

    def is_enrolled(self, node_id: str) -> bool:
        return node_id in self.nodes and self.nodes[node_id].enrolled

    def is_revoked(self, node_id: str) -> bool:
        return node_id in self.revoked

    def get_enrolled_nodes(self) -> List[str]:
        return [nid for nid, n in self.nodes.items() if n.enrolled]

    def get_network_info(self) -> Dict:
        return {
            "total_nodes": len(self.nodes),
            "enrolled_nodes": len([n for n in self.nodes.values() if n.enrolled]),
            "revoked_nodes": len(self.revoked),
            "organizations": list(set(n.organization for n in self.nodes.values())),
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "has_crypto_support": HAS_CRYPTO
        }
