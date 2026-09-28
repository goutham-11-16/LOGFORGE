# LOGFORGE: Universal Log Pre-processing Framework (ULPF)
## Technical Evaluation Presentation (SIH26156) — 5 Slides

---

### SLIDE 1: Title & Executive Overview
* **Title:** LOGFORGE — Universal Log Pre-processing Framework (ULPF)
* **Problem ID:** SIH26156
* **Target Domain:** Perimeter Network Security & Data Standardization
* **The Mission:** 
  * Ingest heterogeneous, multi-vendor network logs (Syslog, CEF, LEEF, JSON, CSV, Cisco ASA).
  * Automatically detect formats and normalize fields into a unified Universal Event Schema.
  * Guarantee 100% lossless retention for legal compliance and forensic auditability.
  * Deliver high-throughput, air-gapped readiness with zero cloud dependencies.

---

### SLIDE 2: The Perimeter Data Problem
* **The Enterprise Challenge:**
  * Multi-vendor infrastructure generates silos: Palo Alto, Cisco ASA, Fortinet, Suricata, and PulseSecure VPN use contradictory syntax for identical concepts.
  * *Example:* `src`, `src_ip`, `sourceAddress`, and `s_ip` all represent an origin IP address.
  * Security teams spend up to 40% of their time developing ad-hoc parsers rather than hunting threats.
* **Why Existing Tools Fall Short:**
  * Heavy SIEM agents either discard raw data to save disk (destroying forensic validity) or maintain proprietary schemas requiring vendor lock-in.

---

### SLIDE 3: System Architecture & The 6-Stage Pipeline
* **Pipeline Flow:**
  1. **Ingestion Subsystem:** Accepts File Uploads (.log, .csv, .json), Raw Paste, Batch multi-files, and live stream feeds.
  2. **Intelligent Parser Registry:** Format auto-detection with multi-token confidence scoring (0.0 to 1.0) and modular parser selection (Syslog RFC 3164/5424, CEF, LEEF, JSON, CSV, Cisco Key-Value).
  3. **Normalization & Taxonomy Engine:** Standardizes network 5-tuple, actions (`allow`/`deny`), severities, and timestamps into ISO-8601 UTC.
  4. **Validation & Isolation:** Validates schema bounds; routes corrupt lines to a Quarantined Repository without pipeline disruption.
  5. **Air-Gapped Storage:** High-concurrency SQLite WAL engine with multi-column B-Tree indexing.
  6. **Export & AI/ML Ready Hub:** JSON, JSONL, and tabular CSV for instant ML anomaly detection and SIEM ingestion.

---

### SLIDE 4: Key Innovations & Lossless Forensic Traceability
* **100% Lossless Guarantee:**
  * Every normalized event stores the raw unedited byte stream in `raw_event`.
  * Preserves cryptographic integrity for forensic admissibility and regulatory compliance.
* **Side-by-Side Traceability Inspector:**
  * Security analysts can view the normalized schema side-by-side with the original raw log and inspect the entire transformation lineage.
* **Air-Gapped Resilience:**
  * Runs entirely on local compute. No external LLMs, no cloud databases, zero telemetry leakage.
* **Benchmark Throughput:**
  * Demonstrates real measured throughput of **15,000+ events/second** on standard commodity hardware.

---

### SLIDE 5: Evaluation Deliverables & Implementation Roadmap
* **Deliverables Ready for Evaluation:**
  * ✅ **Source Code:** Full working Python FastAPI backend + modern React frontend.
  * ✅ **Automated Test Suite:** Comprehensive test coverage for all parsers, normalizers, and exporters (100% pass rate).
  * ✅ **Synthetic Multi-Vendor Dataset:** 6,000+ pre-packaged logs covering 5 perimeter sources.
  * ✅ **Containerization:** Production Dockerfile and docker-compose.yml for one-command deployment.
  * ✅ **Documentation:** 2-page Architecture Document, 2-minute Demo Script, and Quickstart README.
* **Next-Phase Scalability Roadmap:**
  * Distributed stream ingestion via Kafka / Apache Flink for horizontal scaling to billions of events/day.
  * Direct Parquet column-storage export for enterprise data lakes (Snowflake, Databricks).
