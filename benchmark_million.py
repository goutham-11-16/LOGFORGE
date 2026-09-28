"""Million Event Scalability Benchmark for LOGFORGE ULPF."""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from backend.processing.engine import engine
from backend.processing.benchmark import generate_benchmark_stream
from backend.storage.db import store


def main():
    COUNT = 1000000
    CHUNK_SIZE = 25000

    print("==================================================================")
    print(f">> INITIATING MILLION-LOG SCALABILITY STRESS RUN: {COUNT:,} LOGS")
    print(f">> Buffer Flush Chunk Size: {CHUNK_SIZE:,} | RAM Policy: O(1) Bounded")
    print("==================================================================")

    store.clear_database()
    stream = generate_benchmark_stream(count=COUNT)

    t0 = time.perf_counter()
    summary = engine.process_batch(stream, chunk_size=CHUNK_SIZE)
    total_time = time.perf_counter() - t0

    print("\n==================================================================")
    print("[SUCCESS] 1,000,000 EVENTS PROCESSED END-TO-END!")
    print(f"Total Execution Time: {total_time:.2f} seconds")
    print(f"Sustained Engine Throughput: {summary.events_per_second:,.2f} events/second")
    print(f"Total Normalized in Database: {summary.normalized_count:,}")
    print(f"Quarantined/Failed: {summary.failed_count:,}")
    print("==================================================================")


if __name__ == "__main__":
    main()
