"""
Smart contract engine for B-NIDS.
Implements chaincode-like logic for alert validation, reputation management,
and automated escalation.
"""

import time
import hashlib
import json
import threading
from typing import Dict, List, Any
from enum import Enum
from dataclasses import dataclass, field


class ContractStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass
class ContractExecution:
    contract_name: str
    function_name: str
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    status: ContractStatus
    execution_time_ms: float
    timestamp: float = field(default_factory=time.time)
    gas_used: int = 0


class SmartContract:
    """Base class for smart contracts (chaincode)."""

    def __init__(self, name: str):
        self.name = name
        self.state: Dict[str, Any] = {}
        self.execution_log: List[ContractExecution] = []
        self.lock = threading.Lock()

    def execute(self, function_name: str, args: Dict[str, Any]) -> ContractExecution:
        start = time.time()
        try:
            method = getattr(self, function_name, None)
            if method is None or not callable(method):
                ex = ContractExecution(
                    self.name, function_name, args,
                    {"error": f"Function '{function_name}' not found"},
                    ContractStatus.FAILED, 0
                )
                self.execution_log.append(ex)
                return ex
            result = method(**args)
            elapsed = (time.time() - start) * 1000
            ex = ContractExecution(
                self.name, function_name, args,
                result if isinstance(result, dict) else {"result": result},
                ContractStatus.SUCCESS, round(elapsed, 3),
                gas_used=len(json.dumps(args, default=str)) * 68 + 21000
            )
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            ex = ContractExecution(
                self.name, function_name, args,
                {"error": str(e)}, ContractStatus.FAILED, round(elapsed, 3)
            )
        self.execution_log.append(ex)
        return ex


class AlertValidationContract(SmartContract):
    """Validates intrusion alerts before blockchain commitment."""

    REQUIRED_FIELDS = {"alert_type", "severity", "confidence", "source_ip", "timestamp"}
    VALID_ALERT_TYPES = {
        "BENIGN", "DDoS", "DoS", "PortScan", "BruteForce",
        "Infiltration", "Botnet", "WebAttack", "Malware",
        "SQL_Injection", "XSS", "unknown"
    }

    def __init__(self):
        super().__init__("AlertValidation")
        self.state = {"total_validated": 0, "total_rejected": 0,
                       "severity_counts": {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}}

    def validate_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        errors, warnings = [], []
        missing = self.REQUIRED_FIELDS - set(alert.keys())
        if missing:
            errors.append(f"Missing required fields: {missing}")

        severity = alert.get("severity", 0)
        if not isinstance(severity, (int, float)) or not (1 <= severity <= 5):
            errors.append(f"Invalid severity: {severity} (must be 1-5)")

        confidence = alert.get("confidence", -1)
        if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 1):
            errors.append(f"Invalid confidence: {confidence} (must be 0-1)")

        alert_type = alert.get("alert_type", "")
        if alert_type and alert_type not in self.VALID_ALERT_TYPES:
            warnings.append(f"Non-standard alert type: {alert_type}")

        ts = alert.get("timestamp", 0)
        if ts and ts > time.time() + 300:
            errors.append("Alert timestamp is in the future")

        is_valid = len(errors) == 0
        with self.lock:
            if is_valid:
                self.state["total_validated"] += 1
                sev = int(severity) if isinstance(severity, (int, float)) and 1 <= severity <= 5 else 0
                if sev:
                    self.state["severity_counts"][sev] += 1
            else:
                self.state["total_rejected"] += 1

        evidence_digest = hashlib.sha256(
            json.dumps(alert, sort_keys=True, default=str).encode()
        ).hexdigest()

        return {
            "valid": is_valid, "errors": errors, "warnings": warnings,
            "evidence_digest": evidence_digest,
            "validation_timestamp": time.time(), "contract": self.name
        }

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            return dict(self.state)


class ReputationContract(SmartContract):
    """Manages node reputation scores based on behavior."""

    ADJUSTMENTS = {
        "valid_alert": 2.0, "invalid_alert": -5.0,
        "false_positive": -3.0, "true_positive": 5.0,
        "consensus_participation": 1.0, "consensus_violation": -10.0,
        "timely_report": 1.5, "late_report": -1.0
    }

    def __init__(self, initial_score: float = 100.0):
        super().__init__("Reputation")
        self.initial_score = initial_score
        self.state = {"scores": {}, "history": []}

    def _ensure_node(self, node_id: str):
        if node_id not in self.state["scores"]:
            self.state["scores"][node_id] = {
                "score": self.initial_score, "valid_submissions": 0,
                "invalid_submissions": 0, "false_positives": 0,
                "true_positives": 0, "last_updated": time.time()
            }

    def register_node(self, node_id: str) -> Dict[str, Any]:
        with self.lock:
            self._ensure_node(node_id)
            return {"node_id": node_id, "score": self.state["scores"][node_id]["score"]}

    def update_reputation(self, node_id: str, event_type: str,
                          details: str = "") -> Dict[str, Any]:
        with self.lock:
            self._ensure_node(node_id)
            rep = self.state["scores"][node_id]
            old = rep["score"]
            delta = self.ADJUSTMENTS.get(event_type, 0)
            rep["score"] = max(0, min(200, rep["score"] + delta))
            counter_map = {
                "valid_alert": "valid_submissions", "invalid_alert": "invalid_submissions",
                "false_positive": "false_positives", "true_positive": "true_positives"
            }
            if event_type in counter_map:
                rep[counter_map[event_type]] += 1
            rep["last_updated"] = time.time()
            self.state["history"].append({
                "node_id": node_id, "event_type": event_type,
                "delta": delta, "old_score": old, "new_score": rep["score"],
                "timestamp": time.time(), "details": details
            })
            if len(self.state["history"]) > 1000:
                self.state["history"] = self.state["history"][-500:]
            return {"node_id": node_id, "old_score": old,
                    "new_score": rep["score"], "delta": delta}

    def get_reputation(self, node_id: str) -> Dict[str, Any]:
        with self.lock:
            if node_id in self.state["scores"]:
                return {"node_id": node_id, **self.state["scores"][node_id]}
            return {"node_id": node_id, "score": 0, "error": "Not found"}

    def get_all_reputations(self) -> Dict[str, Any]:
        with self.lock:
            scores = self.state["scores"]
            return {
                "scores": dict(scores), "total_nodes": len(scores),
                "average_score": (sum(n["score"] for n in scores.values()) / len(scores)
                                  if scores else 0)
            }

    def is_trusted(self, node_id: str, min_score: float = 50.0) -> bool:
        with self.lock:
            return self.state["scores"].get(node_id, {}).get("score", 0) >= min_score


class EscalationContract(SmartContract):
    """Automated alert escalation based on severity patterns and thresholds."""

    def __init__(self):
        super().__init__("Escalation")
        self.state = {
            "rules": [
                {"name": "critical_severity", "condition": "severity >= 4",
                 "action": "immediate_escalation"},
                {"name": "repeated_source", "condition": "same_source >= 5",
                 "action": "source_quarantine"},
                {"name": "low_conf_high_sev", "condition": "conf < 0.5 & sev >= 3",
                 "action": "manual_review"},
                {"name": "ddos_pattern", "condition": "DDoS count >= 10",
                 "action": "ddos_mitigation"},
            ],
            "escalated_alerts": [], "source_counts": {},
            "type_counts": {}, "total_escalations": 0
        }

    def evaluate_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        severity = alert.get("severity", 0)
        confidence = alert.get("confidence", 1.0)
        alert_type = alert.get("alert_type", "unknown")
        source_ip = alert.get("source_ip", "unknown")
        triggered, actions = [], []

        with self.lock:
            self.state["source_counts"][source_ip] = \
                self.state["source_counts"].get(source_ip, 0) + 1
            src_count = self.state["source_counts"][source_ip]
            self.state["type_counts"][alert_type] = \
                self.state["type_counts"].get(alert_type, 0) + 1
            type_count = self.state["type_counts"][alert_type]

        if severity >= 4:
            triggered.append("critical_severity")
            actions.append({"action": "immediate_escalation", "priority": "CRITICAL",
                            "reason": f"Severity {severity} >= 4"})
        if src_count >= 5:
            triggered.append("repeated_source")
            actions.append({"action": "source_quarantine", "priority": "HIGH",
                            "reason": f"{source_ip} has {src_count} alerts"})
        if confidence < 0.5 and severity >= 3:
            triggered.append("low_conf_high_sev")
            actions.append({"action": "manual_review", "priority": "MEDIUM",
                            "reason": f"Confidence {confidence:.2f} with severity {severity}"})
        if alert_type in ("DDoS", "DoS") and type_count >= 10:
            triggered.append("ddos_pattern")
            actions.append({"action": "ddos_mitigation", "priority": "CRITICAL",
                            "reason": f"{type_count} {alert_type} alerts"})

        if triggered:
            with self.lock:
                self.state["total_escalations"] += 1
                self.state["escalated_alerts"].append({
                    "digest": hashlib.sha256(
                        json.dumps(alert, sort_keys=True, default=str).encode()
                    ).hexdigest()[:16],
                    "rules": triggered, "timestamp": time.time()
                })
                if len(self.state["escalated_alerts"]) > 1000:
                    self.state["escalated_alerts"] = self.state["escalated_alerts"][-500:]

        return {"escalated": len(triggered) > 0, "triggered_rules": triggered,
                "actions": actions, "contract": self.name}

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "total_escalations": self.state["total_escalations"],
                "rules": self.state["rules"],
                "top_sources": dict(sorted(self.state["source_counts"].items(),
                                           key=lambda x: x[1], reverse=True)[:10]),
                "type_distribution": dict(self.state["type_counts"]),
                "recent": self.state["escalated_alerts"][-20:]
            }


class SmartContractEngine:
    """Orchestrates all smart contracts through alert processing pipeline."""

    def __init__(self):
        self.alert_validator = AlertValidationContract()
        self.reputation = ReputationContract()
        self.escalation = EscalationContract()
        self.contracts = {
            "AlertValidation": self.alert_validator,
            "Reputation": self.reputation,
            "Escalation": self.escalation
        }
        self.total_executions = 0
        self.total_time_ms = 0.0
        self.lock = threading.Lock()

    def process_alert(self, alert: Dict[str, Any],
                      submitter_node: str = "default") -> Dict[str, Any]:
        """Full pipeline: validate -> escalate -> update reputation."""
        start = time.time()
        validation = self.alert_validator.execute("validate_alert", {"alert": alert})
        result = {
            "validation": validation.output_data,
            "validation_status": validation.status.value,
            "validation_time_ms": validation.execution_time_ms
        }

        if validation.status != ContractStatus.SUCCESS or \
                not validation.output_data.get("valid"):
            self.reputation.execute("update_reputation", {
                "node_id": submitter_node, "event_type": "invalid_alert",
                "details": json.dumps(validation.output_data.get("errors", []))
            })
            result["accepted"] = False
            result["reputation_update"] = "penalized"
        else:
            self.reputation.execute("update_reputation", {
                "node_id": submitter_node, "event_type": "valid_alert"
            })
            result["accepted"] = True
            result["reputation_update"] = "rewarded"
            esc = self.escalation.execute("evaluate_alert", {"alert": alert})
            result["escalation"] = esc.output_data
            result["escalation_time_ms"] = esc.execution_time_ms

        total = (time.time() - start) * 1000
        result["total_processing_time_ms"] = round(total, 3)
        with self.lock:
            self.total_executions += 1
            self.total_time_ms += total
        return result

    def get_engine_stats(self) -> Dict[str, Any]:
        with self.lock:
            avg = self.total_time_ms / self.total_executions \
                if self.total_executions > 0 else 0
        return {
            "total_executions": self.total_executions,
            "avg_execution_time_ms": round(avg, 3),
            "contracts": {
                name: {"executions": len(c.execution_log)}
                for name, c in self.contracts.items()
            },
            "alert_validation": self.alert_validator.get_stats(),
            "reputation": self.reputation.get_all_reputations(),
            "escalation": self.escalation.get_stats()
        }
