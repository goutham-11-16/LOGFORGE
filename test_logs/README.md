# LOGFORGE Test Log Suite (SIH 26156)

This folder contains pre-configured, production-grade test files covering multiple enterprise security vendors, protocols, and volume tiers.

---

## Available Test Files & Formats

| File Name | Format | Primary Vendor / Technology | Description |
| :--- | :--- | :--- | :--- |
| [`palo_alto_firewall.log`](file:///d:/project%20files/LOG%20ANALYSER/test_logs/palo_alto_firewall.log) | Syslog RFC 5424 | Palo Alto PAN-OS | Next-Gen Firewall traffic, threat signatures, allow/deny rules. |
| [`checkpoint_perimeter.cef`](file:///d:/project%20files/LOG%20ANALYSER/test_logs/checkpoint_perimeter.cef) | ArcSight CEF | Check Point SmartDefense | Perimeter gateway SYN floods, dropped packets, VPN authentications. |
| [`cisco_asa_edge.log`](file:///d:/project%20files/LOG%20ANALYSER/test_logs/cisco_asa_edge.log) | Key-Value / Syslog | Cisco ASA Edge Firewalls | `%ASA-4-106023` and `%ASA-6-302013` connection build/teardown events. |
| [`suricata_ids_alerts.json`](file:///d:/project%20files/LOG%20ANALYSER/test_logs/suricata_ids_alerts.json) | JSON (Suricata EVE) | Suricata / Snort IDS | Structured JSON intrusion alerts, flow telemetry, signature IDs. |
| [`pulsesecure_vpn.csv`](file:///d:/project%20files/LOG%20ANALYSER/test_logs/pulsesecure_vpn.csv) | CSV Tabular | Pulse Secure / Ivanti VPN | User authentication, MFA verification, remote access audit logs. |
| [`mixed_enterprise_feed.log`](file:///d:/project%20files/LOG%20ANALYSER/test_logs/mixed_enterprise_feed.log) | Heterogeneous Multi-Vendor | Mixed (100 events) | Random interleaved logs to evaluate automatic format detection. |
| [`stress_batch_1000.log`](file:///d:/project%20files/LOG%20ANALYSER/test_logs/stress_batch_1000.log) | High-Volume Batch | Enterprise Stream (1,000 events) | Batch file ingestion stress test evaluating sub-second throughput. |
| [`test_logs_bundle.zip`](file:///d:/project%20files/LOG%20ANALYSER/test_logs/test_logs_bundle.zip) | ZIP Archive | Complete Test Bundle | Contains all test files bundled together for easy export. |

---

## 3 Ways to Test

### 1. Web UI Batch File Upload (Recommended)
1. Open the portal at `http://localhost:3001/`.
2. Click **Ingest Logs** in the top navigation or switch to the **Ingestion & Stream** tab.
3. Under **Batch File Ingestion**, click **Select File** and pick any file (e.g. `stress_batch_1000.log` or `mixed_enterprise_feed.log`).
4. Watch the system normalize all events with sustained throughput (15,000+ eps) and update the live Dashboard!

### 2. Copy-Paste Raw Stream
1. Open any log file in a text editor (e.g. `palo_alto_firewall.log`).
2. Copy the text and paste it into the **Paste Raw Log Stream** box on the portal.
3. Leave format on **Auto-Detect Format (Recommended)** and click **Parse & Standardize Logs**.
4. Check the **Event Explorer** tab to inspect the extracted 5-tuple and lossless raw event.

### 3. Engine Diagnostics (1,000 to 1,000,000 Logs)
1. Navigate to the **Engine Diagnostics** tab.
2. Select any volume tier:
   - **1,000 Events:** Sub-second micro-burst (~0.05s)
   - **10,000 Events:** Standard batch (~0.5s)
   - **50,000 Events:** Heavy ingest (~2.8s)
   - **100,000 Events:** Enterprise run (~6.2s)
   - **1,000,000 Events:** Million-scale stress run (~71s)
3. Click **Launch Event Run** to measure real-time ingestion latency, throughput, and $O(1)$ memory consumption.
