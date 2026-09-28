# SIH26156 — Universal Log Pre-processing Framework

## Project Name: ULPF — Universal Log Pre-processing Framework

## Product Name: LOGFORGE

You are the lead software architect, backend engineer, data engineer, cybersecurity engineer, frontend engineer, DevOps engineer, UI/UX designer, QA engineer, and technical documentation engineer.

Your task is to build a complete, production-quality prototype for:

**SIH26156 — Universal Log Pre-processing Framework (ULPF)**

Do not build a fake dashboard or a UI-only prototype.

The core log-processing engine must actually work.

---

# 1. PROBLEM STATEMENT

Modern enterprises generate logs from:

* Network devices
* Firewalls
* Routers
* Servers
* Operating systems
* Applications
* Databases
* Cloud services
* Containers
* Endpoint security systems
* IAM systems
* IoT devices
* Other hardware/software systems

These logs may use completely different formats.

Examples:

* Syslog
* JSON
* XML
* CSV
* CEF
* LEEF
* Vendor-specific formats
* Application-specific formats

The system must transform heterogeneous log events into a common, standardized, lossless, analytics-ready representation.

The current SIH scope focuses on:

**Perimeter network device-generated logs/events regardless of source, format, vendor, or technology.**

---

# 2. CORE PRODUCT

Build:

# LOGFORGE

### Universal Log Pre-processing Framework

The product should accept heterogeneous raw network logs and convert them into a standardized universal event schema.

The fundamental pipeline is:

```text
RAW LOG
   ↓
INGESTION
   ↓
FORMAT DETECTION
   ↓
SOURCE DETECTION
   ↓
PARSING
   ↓
FIELD EXTRACTION
   ↓
NORMALIZATION
   ↓
VALIDATION
   ↓
UNIVERSAL EVENT SCHEMA
   ↓
OUTPUT
```

The original event must ALWAYS be preserved.

---

# 3. MOST IMPORTANT REQUIREMENT

Never discard the original event.

For every normalized event maintain:

```text
raw_event
```

and a unique identifier:

```text
event_id
```

The system must allow the user to trace:

```text
NORMALIZED EVENT
       ↓
PROCESSING METADATA
       ↓
ORIGINAL RAW EVENT
```

This is required for forensic and compliance purposes.

---

# 4. INPUTS

Support multiple input mechanisms.

## A. File Upload

Allow:

```text
.log
.txt
.json
.jsonl
.csv
.xml
```

Users should be able to drag and drop files.

---

## B. Paste Log

Provide:

```text
Paste Raw Log
```

textarea.

---

## C. Batch Upload

Allow multiple files simultaneously.

Example:

```text
firewall.log
router.json
vpn.csv
ids.log
```

---

## D. Streaming Input

Create an architecture capable of accepting streamed events.

For the prototype, provide a simulated live stream if necessary.

Do not require cloud services.

---

# 5. LOG FORMAT DETECTION

Automatically identify the input format.

Examples:

```text
JSON
CSV
XML
SYSLOG
CEF
LEEF
PLAIN TEXT
CUSTOM
```

Display:

```text
Detected Format: SYSLOG
Confidence: 98%
```

If automatic detection fails:

```text
Unknown format
```

allow the user to manually select a parser.

---

# 6. SOURCE DETECTION

Detect or allow selection of source type:

```text
Firewall
Router
Switch
VPN Gateway
IDS/IPS
Proxy
Load Balancer
Network Gateway
Other
```

Display:

```text
Vendor: ExampleVendor
Device Type: Firewall
Parser: firewall-v1
```

Do not falsely identify a vendor when the evidence is insufficient.

---

# 7. PARSER ARCHITECTURE

Build a modular parser system.

Use a structure similar to:

```text
/parsers
    /syslog
    /json
    /csv
    /cef
    /leef
    /custom
```

Each parser should implement a common interface.

Example conceptual interface:

```text
detect()
parse()
validate()
normalize()
```

The architecture must make it easy to add a new parser without rewriting the entire application.

---

# 8. UNIVERSAL EVENT SCHEMA

Create a clearly documented universal event schema.

Example:

```json
{
  "event_id": "evt_000001",
  "timestamp": "2026-09-28T18:32:14Z",

  "source": {
    "vendor": "ExampleVendor",
    "device_type": "firewall",
    "hostname": "fw01",
    "ip": "192.168.1.1"
  },

  "event": {
    "category": "network",
    "type": "connection",
    "action": "allow",
    "severity": "low"
  },

  "network": {
    "source_ip": "192.168.1.25",
    "destination_ip": "8.8.8.8",
    "source_port": 52341,
    "destination_port": 443,
    "protocol": "TCP"
  },

  "user": {},

  "process": {},

  "metadata": {
    "schema_version": "1.0",
    "parser": "firewall-v1"
  },

  "raw_event": "ORIGINAL LOG HERE"
}
```

Do not assume every field exists.

Missing fields should be represented safely rather than fabricated.

---

# 9. FIELD NORMALIZATION

Different vendors may use:

```text
src
source
src_ip
sourceAddress
sourceIP
```

These should map to:

```text
source_ip
```

Similarly:

```text
dst
destination
dst_ip
destinationAddress
destinationIP
```

should map to:

```text
destination_ip
```

Create a configurable field-mapping layer.

Example:

```text
Vendor Field          Universal Field

src                   source_ip
src_ip                source_ip
sourceAddress         source_ip

dst                   destination_ip
dst_ip                destination_ip
destinationAddress    destination_ip

sport                 source_port
dport                 destination_port

proto                 protocol
action                action
```

Do not hardcode normalization logic directly into the UI.

---

# 10. TRACEABILITY

Every normalized event must contain metadata showing how it was produced.

Example:

```json
{
  "event_id": "evt_000421",

  "processing": {
    "source_format": "CEF",
    "source_type": "firewall",
    "parser": "cef-firewall-v1",
    "schema_version": "1.0",
    "processed_at": "2026-09-28T18:32:15Z"
  }
}
```

The UI should allow:

**View Original**

and:

**View Normalized**

side-by-side.

---

# 11. LOSSLESS PROCESSING

The system must never modify or destroy the original event.

Store:

```text
Raw Event
+
Normalized Event
+
Processing Metadata
```

The user must be able to retrieve the raw event later.

This is a critical feature.

---

# 12. PLUG-AND-PLAY PARSER SYSTEM

Create a parser registry.

Example:

```text
Parser Registry

✓ Syslog
✓ JSON
✓ CSV
✓ CEF
✓ LEEF
✓ Firewall
✓ Router
✓ VPN
✓ IDS
```

Create a mechanism for adding future parsers.

Example:

```text
Add Parser
```

Allow configuration such as:

```json
{
  "name": "example-firewall",
  "vendor": "ExampleVendor",
  "device_type": "firewall",
  "format": "syslog",
  "field_mapping": {}
}
```

The goal is to demonstrate that new sources can be onboarded without modifying the core engine.

---

# 13. PROCESSING ENGINE

Implement a real processing engine.

Input:

```text
Raw events
```

Output:

```text
Normalized events
```

The engine should produce:

```text
total_events
successful_events
failed_events
processing_time
events_per_second
format_distribution
source_distribution
```

---

# 14. ERROR HANDLING

Do not silently discard malformed logs.

Example:

```text
Total events: 10,000

Successfully processed: 9,997

Failed: 3
```

For failures show:

```text
event_id
reason
raw_event
parser
line_number
```

Allow:

**View Error**

and:

**Export Failed Events**

---

# 15. UNIFIED DASHBOARD

Create a professional cybersecurity/data-platform dashboard.

Design it like an enterprise product.

Main dashboard:

```text
┌─────────────────────────────────────────────────────────┐
│ LOGFORGE                              ● ENGINE ONLINE    │
├──────────────┬──────────────┬──────────────┬─────────────┤
│ 1,245,820    │ 1,245,817    │ 3            │ 12         │
│ TOTAL EVENTS │ NORMALIZED   │ FAILED       │ SOURCES     │
├──────────────┴──────────────┴──────────────┴─────────────┤
│                                                         │
│             EVENT PROCESSING TIMELINE                  │
│                                                         │
├─────────────────────────────────────────────────────────┤
│ SOURCE DISTRIBUTION                                     │
│                                                         │
│ Firewall       █████████████████                       │
│ Router         ███████████                             │
│ VPN            ███████                                 │
│ IDS            █████                                   │
├─────────────────────────────────────────────────────────┤
│ RECENT EVENTS                                           │
└─────────────────────────────────────────────────────────┘
```

---

# 16. LIVE PROCESSING VIEW

Create a live processing screen.

Display:

```text
Processing...
```

with:

```text
Events received
Events processed
Events/sec
Success rate
Failed events
Current parser
Current source
```

Use realistic streaming animation based on actual processing.

Do NOT fake statistics while processing real data.

---

# 17. EVENT EXPLORER

Create a powerful searchable event table.

Columns:

```text
Timestamp
Event ID
Source
Vendor
Type
Source IP
Destination IP
Protocol
Action
Severity
Status
```

Features:

* Search
* Filtering
* Sorting
* Pagination
* Date filtering
* Source filtering
* Event type filtering
* Severity filtering

Click an event to open detailed information.

---

# 18. EVENT DETAIL VIEW

Create:

### Normalized Event

Display formatted JSON.

### Original Event

Display exact raw input.

### Processing Metadata

Display:

```text
Parser
Source
Format
Schema version
Processing time
```

### Traceability

Show:

```text
Raw
 ↓
Parser
 ↓
Field Extraction
 ↓
Normalization
 ↓
Validation
 ↓
Universal Event
```

---

# 19. ANALYTICS

Create useful analytics from normalized events.

Examples:

### Event Categories

```text
Network
Authentication
Security
System
Application
```

### Actions

```text
Allow
Deny
Block
Connect
Disconnect
Alert
```

### Protocols

```text
TCP
UDP
ICMP
HTTP
HTTPS
DNS
SSH
```

### Top Source IPs

### Top Destination IPs

### Event Frequency

### Error Rate

### Parser Performance

All analytics must be calculated from actual processed data.

---

# 20. AI/ML READY OUTPUT

The framework itself does not need to invent threats.

Its responsibility is to create clean standardized data that can be consumed by:

```text
SIEM
Data Lake
Threat Analytics
Machine Learning
Anomaly Detection
Threat Hunting
```

Create an export format suitable for downstream ML.

For example:

```text
JSONL
CSV
Parquet
```

Implement JSON/JSONL and CSV first.

If Parquet adds unnecessary complexity, document it as future scope rather than creating a fragile implementation.

---

# 21. EXPORT

Provide:

```text
Export Normalized Events
```

Options:

```text
JSON
JSONL
CSV
```

Also:

```text
Export Processing Report
Export Failed Events
Export Audit Trail
```

---

# 22. SEARCH

Allow searching across normalized events.

Examples:

```text
192.168.1.25
8.8.8.8
DENY
TCP
firewall
evt_000421
```

The search should operate on actual processed data.

---

# 23. AIR-GAPPED OPERATION

The application must be designed to run without internet access.

Do not require:

* OpenAI API
* cloud AI
* cloud database
* remote logging service
* external authentication service
* internet connection

The core processing engine must run locally.

---

# 24. CONTAINERIZATION

Provide a Docker setup.

Create:

```text
Dockerfile
docker-compose.yml
```

The application should be capable of running in an isolated environment.

Example:

```text
docker compose up
```

Document the exact commands.

Do not require external cloud services.

---

# 25. TECHNOLOGY

Preferred stack:

### Frontend

* Next.js
* TypeScript
* Tailwind CSS
* Recharts or lightweight visualization library

### Backend

Use either:

* Python FastAPI

or

* Node.js/TypeScript

Prefer Python FastAPI if it makes the parsing/data-processing engine cleaner.

### Processing

* Python
* Pydantic
* pandas only where useful
* standard parsing libraries where appropriate

### Storage

Start simple.

Use:

* SQLite

or

* PostgreSQL if genuinely needed.

Do not introduce unnecessary infrastructure.

---

# 26. PROJECT ARCHITECTURE

Use clean separation:

```text
logforge/
│
├── frontend/
│
├── backend/
│   ├── ingestion/
│   ├── parsers/
│   ├── normalization/
│   ├── schema/
│   ├── validation/
│   ├── processing/
│   ├── analytics/
│   ├── export/
│   └── api/
│
├── datasets/
│   ├── sample_logs/
│   └── expected_outputs/
│
├── docs/
│
├── tests/
│
├── Dockerfile
├── docker-compose.yml
└── README.md
```

Keep the core processing engine independent from the frontend.

---

# 27. SAMPLE DATA

Create realistic synthetic sample datasets for demonstration.

Include different formats.

Example:

```text
samples/
    firewall_syslog.log
    router_syslog.log
    vpn.json
    ids.csv
    firewall_cef.log
```

Make sure each sample contains enough events to demonstrate:

* successful parsing
* different field names
* different formats
* malformed events
* different timestamps
* different source/destination IPs
* different actions
* different protocols

Do not claim the synthetic data came from real organizations.

Clearly label it:

**Synthetic Demonstration Dataset**

---

# 28. DEMO SCENARIO

Create a one-click:

## DEMO MODE

The judges should be able to click:

**Run Demo**

Then automatically:

```text
Load sample logs
      ↓
Detect formats
      ↓
Select parsers
      ↓
Parse events
      ↓
Normalize events
      ↓
Validate
      ↓
Generate analytics
      ↓
Show dashboard
```

At the end show:

```text
Demo Complete

Events processed: 50,000
Normalized: 49,997
Failed: 3
Sources: 5
Formats: 4

Processing time: XX seconds
```

Use actual measurements from the running system.

---

# 29. PERFORMANCE

The framework should be designed for scalability.

Do not claim that a laptop prototype processes billions of events per day.

Instead:

* Make the processing architecture streaming-friendly.
* Use batch processing where appropriate.
* Avoid loading huge datasets entirely into memory.
* Provide configurable batch sizes.
* Measure events/second.
* Document how the architecture can scale horizontally.

Clearly distinguish:

**Prototype benchmark**

from:

**Production-scale architecture.**

---

# 30. SECURITY

Implement basic security practices:

* Input validation
* File size limits
* Safe file handling
* No arbitrary command execution from uploaded logs
* Sanitization of displayed content
* Avoid exposing sensitive data unnecessarily
* Local-only default operation

Never interpret log contents as executable code.

---

# 31. TESTING

Create automated tests for:

### Parsers

* Syslog
* JSON
* CSV
* CEF
* LEEF where implemented

### Normalization

Test:

```text
src
source
src_ip
source_ip
sourceAddress
```

all mapping correctly to:

```text
source_ip
```

### Traceability

Verify that:

```text
raw_event
```

is exactly preserved.

### Error handling

Test malformed events.

### Export

Test:

```text
JSON
JSONL
CSV
```

### API

Test ingestion and processing endpoints.

### Frontend

Test:

* upload
* processing
* event explorer
* event details
* filters
* exports

---

# 32. IMPORTANT — NO FAKE FEATURES

Do not create:

* fake AI analysis
* fake billion-event claims
* fake processing numbers
* fake threat detection
* fake parser support
* fake integrations
* fake scalability metrics

If something is simulated, clearly label it:

**Simulation / Demonstration**

The core parser and normalization pipeline must be real.

---

# 33. DOCUMENTATION

Create:

## README.md

Include:

* Problem statement
* Product overview
* Architecture
* Data flow
* Universal schema
* Supported formats
* Parser architecture
* Normalization process
* Traceability
* Installation
* Local execution
* Docker execution
* Demo instructions
* Testing
* Sample datasets
* API documentation
* Limitations
* Future scope

---

# 34. ARCHITECTURE DOCUMENT

Create a maximum 2-page architecture document suitable for SIH evaluation.

Include:

```text
Input Sources
      ↓
Ingestion Layer
      ↓
Detection Layer
      ↓
Parser Layer
      ↓
Normalization Layer
      ↓
Validation Layer
      ↓
Universal Schema
      ↓
Storage / Export
      ↓
SIEM / Data Lake / ML
```

Explain:

* Lossless preservation
* Traceability
* Plug-in parsers
* Air-gapped operation
* Scalability

---

# 35. SIH TECHNICAL PRESENTATION

Create content suitable for a maximum 5-slide technical presentation.

### Slide 1

Problem

### Slide 2

Solution / Architecture

### Slide 3

Core Innovation

### Slide 4

Working Demo

### Slide 5

Impact / Scalability / Future Scope

Keep the content technical and concise.

---

# 36. TWO-MINUTE DEMO VIDEO FLOW

Prepare the application so a 2-minute demo can show:

### 0:00–0:15

Problem

Different devices → different log formats.

### 0:15–0:35

Upload multiple log formats.

### 0:35–0:55

Automatic format/source detection.

### 0:55–1:15

Parsing and normalization.

### 1:15–1:35

Show unified events.

### 1:35–1:50

Show raw ↔ normalized traceability.

### 1:50–2:00

Export + analytics + offline architecture.

---

# 37. DEVELOPMENT ORDER

Do NOT start with the dashboard.

Follow this exact order:

### Phase 1

Create universal event schema.

### Phase 2

Build parser interface.

### Phase 3

Implement Syslog parser.

### Phase 4

Implement JSON parser.

### Phase 5

Implement CSV parser.

### Phase 6

Implement CEF parser.

### Phase 7

Implement normalization engine.

### Phase 8

Implement raw-event preservation.

### Phase 9

Implement traceability.

### Phase 10

Implement validation/error handling.

### Phase 11

Create API.

### Phase 12

Create event storage.

### Phase 13

Create analytics.

### Phase 14

Build frontend dashboard.

### Phase 15

Build event explorer.

### Phase 16

Build event detail/traceability view.

### Phase 17

Implement exports.

### Phase 18

Implement demo mode.

### Phase 19

Dockerize.

### Phase 20

Write tests.

### Phase 21

Run complete QA.

### Phase 22

Create SIH documentation.

---

# 38. FINAL ACCEPTANCE TEST

Before declaring the project complete, perform this exact test.

Take these inputs:

```text
firewall_syslog.log
router.json
vpn.csv
ids.cef
```

Upload them simultaneously.

The system must:

```text
1. Detect formats
2. Identify/accept source types
3. Select appropriate parsers
4. Parse events
5. Extract fields
6. Normalize fields
7. Validate events
8. Preserve raw events
9. Assign event IDs
10. Store traceability metadata
11. Display unified events
12. Generate analytics
13. Allow searching/filtering
14. Export normalized data
15. Export failed events
```

Then click one normalized event.

Verify:

```text
Normalized Event
       ↕
Original Raw Event
       ↕
Processing Metadata
       ↕
Parser
```

Then test an intentionally malformed log.

The system must report the error without crashing.

Finally:

```text
docker compose up
```

must start the application successfully without requiring internet access.

---

# 39. FINAL PRODUCT STANDARD

The final application should feel like a real cybersecurity/data engineering product.

It should have:

* polished UI
* functional processing engine
* modular parsers
* universal schema
* lossless raw-event preservation
* traceability
* analytics
* search
* filtering
* exports
* demo mode
* Docker deployment
* offline capability
* automated tests
* documentation

Do not optimize for having hundreds of features.

Optimize for having **a small number of features that actually work end-to-end.**

## FINAL DEMO

The strongest demonstration should be:

```text
             4 DIFFERENT LOG FORMATS

        SYSLOG     JSON     CSV     CEF
           \         |        |       /
            \        |        |      /
             └──── LOGFORGE ───────┘
                       │
                 PARSE + NORMALIZE
                       │
                       ▼
                UNIVERSAL SCHEMA
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       SEARCH       ANALYTICS      EXPORT
          │
          ▼
    RAW ↔ NORMALIZED
     TRACEABILITY
```

The judges should be able to immediately understand:

**“Different devices produce different logs. LOGFORGE converts them into one standardized, traceable, analytics-ready format without losing the original event.”**
