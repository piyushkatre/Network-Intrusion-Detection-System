"""
B-NIDS Blockchain Performance Benchmark
Generates metrics for the research paper.
"""

import sys
import os
import time
import json
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from blockchain_logger import BlockchainLogger

def run_benchmark():
    print("=" * 70)
    print("B-NIDS PERMISSIONED BLOCKCHAIN BENCHMARK")
    print("=" * 70)

    bl = BlockchainLogger(difficulty=2)

    # Simulated intrusion alerts
    ALERT_TYPES = ["DDoS", "DoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "BENIGN"]
    SEVERITIES = {"DDoS": 5, "DoS": 4, "PortScan": 2, "BruteForce": 3, "WebAttack": 3, "Botnet": 5, "BENIGN": 1}

    alerts = []
    for i in range(50):
        atype = random.choice(ALERT_TYPES)
        alerts.append({
            "prediction": atype,
            "alert_type": atype,
            "severity": SEVERITIES[atype],
            "confidence": round(random.uniform(0.3, 0.99), 3),
            "source_ip": f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
            "dest_ip": f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "timestamp": time.time(),
        })

    # Process all alerts
    print(f"\nProcessing {len(alerts)} simulated intrusion alerts...")
    results = []
    for i, alert in enumerate(alerts):
        result = bl.add_transaction(alert)
        results.append(result)
        if (i + 1) % 10 == 0:
            print(f"  Processed {i+1}/{len(alerts)}...")

    # Gather metrics
    stats = bl.get_network_stats()

    committed = [r for r in results if r.get("committed")]
    rejected = [r for r in results if not r.get("committed")]
    times = [r["total_time_ms"] for r in committed]

    # Stage-level metrics
    sc_times = [r["stages"]["smart_contracts"]["processing_time_ms"] for r in committed]
    oc_times = [r["stages"]["off_chain_storage"]["storage_time_ms"] for r in committed]
    consensus_times = [r["stages"]["consensus"]["total_latency_ms"] for r in committed]
    mining_times = [r["stages"]["blockchain"]["mining_time_ms"] for r in committed]

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    print(f"\n--- Alert Processing ---")
    print(f"  Total alerts:      {len(alerts)}")
    print(f"  Committed:         {len(committed)}")
    print(f"  Rejected:          {len(rejected)}")
    print(f"  Commit rate:       {len(committed)/len(alerts)*100:.1f}%")

    print(f"\n--- End-to-End Latency ---")
    print(f"  Average:           {sum(times)/len(times):.3f} ms")
    print(f"  Min:               {min(times):.3f} ms")
    print(f"  Max:               {max(times):.3f} ms")
    print(f"  Median:            {sorted(times)[len(times)//2]:.3f} ms")

    print(f"\n--- Per-Stage Latency (average) ---")
    print(f"  Smart Contracts:   {sum(sc_times)/len(sc_times):.3f} ms")
    print(f"  Off-chain Storage: {sum(oc_times)/len(oc_times):.3f} ms")
    print(f"  PBFT Consensus:    {sum(consensus_times)/len(consensus_times):.3f} ms")
    print(f"  Block Mining:      {sum(mining_times)/len(mining_times):.3f} ms")

    print(f"\n--- Blockchain Metrics ---")
    print(f"  Chain length:      {stats['blockchain']['chain_length']}")
    print(f"  Total txns:        {stats['blockchain']['total_transactions']}")
    print(f"  DB size:           {stats['blockchain']['db_size_kb']:.1f} KB")
    print(f"  Difficulty:        {stats['blockchain']['difficulty']}")

    print(f"\n--- PBFT Consensus ---")
    print(f"  Total rounds:      {stats['consensus']['total_rounds']}")
    print(f"  Success rate:      {stats['consensus']['success_rate_pct']}%")
    print(f"  Nodes:             {stats['consensus']['total_nodes']}")
    print(f"  Fault tolerance:   f={stats['consensus']['fault_tolerance_f']}")
    print(f"  Quorum:            {stats['consensus']['quorum_size']}")

    print(f"\n--- Smart Contracts ---")
    print(f"  Total executions:  {stats['smart_contracts']['total_executions']}")
    print(f"  Avg time:          {stats['smart_contracts']['avg_execution_time_ms']:.3f} ms")
    val = stats['smart_contracts']['alert_validation']
    print(f"  Alerts validated:  {val['total_validated']}")
    print(f"  Alerts rejected:   {val['total_rejected']}")
    print(f"  Severity dist:     {val['severity_counts']}")

    print(f"\n--- Off-Chain Storage ---")
    print(f"  Total stored:      {stats['off_chain_storage']['total_stored']}")
    print(f"  Total size:        {stats['off_chain_storage']['total_mb']:.2f} MB")

    print(f"\n--- Network Identity ---")
    net = stats['network']['identity']
    print(f"  Total nodes:       {net['total_nodes']}")
    print(f"  Organizations:     {net['organizations']}")
    print(f"  Crypto support:    {net['has_crypto_support']}")

    # Chain validation benchmark
    print(f"\n--- Chain Validation Benchmark ---")
    val_result = bl.network.verify_chain()
    print(f"  Valid:             {val_result['valid']}")
    print(f"  Blocks checked:    {val_result['blocks_checked']}")
    print(f"  Validation time:   {val_result['validation_time_ms']:.3f} ms")

    # Forensic search benchmark
    start = time.time()
    search_results = bl.forensic_search(min_severity=4)
    search_time = (time.time() - start) * 1000
    print(f"\n--- Forensic Search Benchmark ---")
    print(f"  Query: severity >= 4")
    print(f"  Results found:     {len(search_results)}")
    print(f"  Search time:       {search_time:.3f} ms")

    # Evidence verification benchmark
    if committed:
        evidence_hash = committed[0]["stages"]["off_chain_storage"]["content_hash"]
        start = time.time()
        verify = bl.verify_evidence(evidence_hash)
        verify_time = (time.time() - start) * 1000
        print(f"\n--- Evidence Verification ---")
        print(f"  Hash:              {evidence_hash[:16]}...")
        print(f"  Exists:            {verify.get('exists')}")
        print(f"  Valid:             {verify.get('valid')}")
        print(f"  Verification time: {verify_time:.3f} ms")

    # Throughput
    total_time_sec = sum(times) / 1000
    throughput = len(committed) / total_time_sec if total_time_sec > 0 else 0
    print(f"\n--- Throughput ---")
    print(f"  Alerts/second:     {throughput:.1f}")

    print("\n" + "=" * 70)
    print("BENCHMARK COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
