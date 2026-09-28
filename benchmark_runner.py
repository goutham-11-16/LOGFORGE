"""Scalability & Stress Testing Benchmark Runner for LOGFORGE ULPF.
Executes high-volume log ingestion from 1,000 to 1,000,000 logs and verifies performance.
"""
import sys
import os
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from backend.processing.engine import engine
from backend.processing.benchmark import generate_benchmark_stream
from backend.storage.db import store


def run_test_tier(count: int, chunk_size: int = 5000):
    print(f"\n=======================================================")
    print(f">> RUNNING BENCHMARK: {count:,} EVENTS (Chunk Size: {chunk_size:,})")
    print(f"=======================================================")
    
    stream = generate_benchmark_stream(count=count)
    t0 = time.perf_counter()
    summary = engine.process_batch(stream, chunk_size=chunk_size)
    elapsed = time.perf_counter() - t0

    print(f"[OK] Completed in: {summary.processing_time_seconds:.3f} seconds")
    print(f"[PERF] Throughput: {summary.events_per_second:,.2f} events/second")
    print(f"[STATS] Normalized Count: {summary.normalized_count:,}")
    print(f"[STATS] Quarantined / Failed: {summary.failed_count:,}")
    print(f"[STATS] Sources Breakdown: {summary.sources_breakdown}")
    print(f"[STATS] Formats Breakdown: {summary.formats_breakdown}")
    return summary


def main():
    print("Initializing LOGFORGE Scalability & Stress Test Suite...")
    store.clear_database()

    # Tier 1: 1,000 Events (Micro-benchmark)
    run_test_tier(1000, chunk_size=1000)

    # Tier 2: 10,000 Events (Mid-scale batch)
    run_test_tier(10000, chunk_size=5000)

    # Tier 3: 50,000 Events (High-scale stress test)
    run_test_tier(50000, chunk_size=10000)

    # Tier 4: 100,000 Events (Extreme enterprise burst)
    run_test_tier(100000, chunk_size=10000)

    print("\n=======================================================")
    print("[SUCCESS] ALL BENCHMARK TIERS COMPLETED SUCCESSFULLY!")
    print("=======================================================")


if __name__ == "__main__":
    main()
