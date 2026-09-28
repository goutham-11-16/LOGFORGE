# LOGFORGE (SIH26156) — 2-Minute Demonstration Script
## Step-by-Step Guide for Judges & Technical Evaluators

---

### Timing Breakdown (120 Seconds Total)

#### [00:00 - 00:25] The Problem & Introduction
* **Visual:** Open browser to `http://localhost:3000` (or `http://localhost:8000`). Display the sleek cybersecurity dark-mode dashboard with the green pulsing `ENGINE ONLINE` badge.
* **Speaker Script:**
  > *"Modern enterprise perimeters are overwhelmed by disparate log formats from Cisco firewalls, Palo Alto appliances, Suricata IDS, and VPN gateways. Security teams waste hundreds of hours writing ad-hoc parsers. LOGFORGE solves this with a Universal Log Pre-processing Framework that ingests, parses, normalizes, and retains 100% of raw events for strict forensic compliance—all running air-gapped without external cloud dependencies."*

#### [00:25 - 00:55] 1-Click Multi-Vendor Demo Execution
* **Action:** Click the glowing green **"Run 1-Click Demo"** button on the top right.
* **Visual:** Watch the live ingestion benchmark banner trigger:
  * **6,000+ multi-vendor events** (Palo Alto Syslog, Cisco ASA key-value, ArcSight CEF, IBM QRadar LEEF, Suricata EVE JSON, VPN CSV) ingested and processed simultaneously.
  * Real-time benchmark banner appears: displays throughput (e.g., ~15,000 to 20,000 events/second) and sub-second execution latency.
* **Speaker Script:**
  > *"With one click, our engine auto-detected formats across 6 disparate protocols and normalized 6,000+ real-world perimeter events in less than half a second. Notice the 100% lossless badge: every raw byte is preserved in SQLite WAL storage for forensic audits."*

#### [00:55 - 01:25] Event Explorer & Side-by-Side Traceability Inspector
* **Action:** Switch to the **"Event Explorer"** tab.
  1. Filter by `Action: Deny` and search `outside_access_in`.
  2. Click the **"Inspect"** button on a Cisco ASA or Palo Alto event to trigger the Forensic Modal.
* **Visual:** Show the side-by-side comparison modal:
  * Left: Normalized Universal Event JSON with standardized fields (`network.source_ip`, `network.destination_port`, `event.action: deny`).
  * Right: Exact unmodified raw log line with the `100% UNMODIFIED` badge.
  * Top: Pipeline traceability lineage showing `Raw Ingest ➔ Detection ➔ Parser ➔ Normalization ➔ Schema Validation`.
* **Speaker Script:**
  > *"In our Event Explorer, disparate vendor fields like `src`, `src_ip`, and `sourceAddress` are unified into `network.source_ip`. By clicking 'Inspect', security auditors can verify complete end-to-end traceability—comparing the normalized schema against the exact raw byte stream."*

#### [01:25 - 01:45] Malformed Logs & Quarantine Resilience
* **Action:** Point out the **"Quarantined / Failed"** KPI counter on the dashboard.
* **Speaker Script:**
  > *"When corrupted or malformed lines arrive, LOGFORGE never crashes the pipeline. Instead, corrupt logs are isolated into a forensic quarantine repository with failure diagnostics, ensuring zero data loss and uninterrupted pipeline operation."*

#### [01:45 - 02:00] Downstream SIEM & AI/ML Export
* **Action:** Click the **"SIEM Export"** tab and demonstrate one-click downloads:
  * `.jsonl` for Elasticsearch, Splunk, and BigQuery.
  * `.csv` for Scikit-learn and anomaly detection pipelines.
* **Speaker Script:**
  > *"Finally, LOGFORGE exports structured datasets into streaming JSONL or tabular CSV for downstream SIEM correlation, Data Lakes, or AI/ML threat hunting. Everything is containerized and ready for air-gapped deployment."*
