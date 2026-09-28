"""FastAPI Application Entry Point for LOGFORGE ULPF."""
from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import os
import glob
import time

from backend.schema.models import BatchProcessSummary
from backend.parsers.registry import registry
from backend.processing.engine import engine
from backend.storage.db import store
from backend.export.exporter import exporter

app = FastAPI(
    title="LOGFORGE — Universal Log Pre-processing Framework (ULPF)",
    description="SIH26156 production-quality log normalization & forensics engine.",
    version="1.0.0"
)

# CORS setup for Next.js frontend on port 3000
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "engine": "LOGFORGE-ULPF",
        "version": "1.0.0",
        "parsers_loaded": len(registry.list_parsers())
    }


@app.get("/api/parsers")
def get_parsers():
    return {
        "parsers": registry.list_parsers()
    }


@app.post("/api/ingest/paste")
def ingest_pasted_log(
    raw_logs: str = Form(...),
    forced_parser: Optional[str] = Form(None)
):
    """Ingest raw log text pasted in the UI."""
    lines = [line.strip() for line in raw_logs.splitlines() if line.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="No log entries provided.")

    summary = engine.process_batch(lines, forced_parser=forced_parser)
    return summary


@app.post("/api/ingest/file")
async def ingest_log_file(
    file: UploadFile = File(...),
    forced_parser: Optional[str] = Form(None)
):
    """Upload and process a log file (.log, .txt, .json, .csv, etc.)."""
    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"File decoding error: {str(e)}")

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    summary = engine.process_batch(lines, forced_parser=forced_parser)
    return summary


@app.post("/api/demo/run")
def run_one_click_demo():
    """
    One-Click Demo Mode:
    Ingests all multi-vendor synthetic test suites from datasets/sample_logs/
    and benchmarks actual processing time, success counts, and throughput.
    """
    dataset_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "datasets", "sample_logs")
    log_files = glob.glob(os.path.join(dataset_dir, "*.*"))
    if not log_files:
        raise HTTPException(status_code=404, detail="Synthetic datasets not found.")

    all_lines = []
    for fp in log_files:
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    clean = line.strip()
                    if clean:
                        all_lines.append(clean)
        except Exception:
            continue

    if not all_lines:
        raise HTTPException(status_code=500, detail="Failed to load demonstration dataset lines.")

    # Process all lines through the real engine
    summary = engine.process_batch(all_lines)
    return summary


@app.post("/api/benchmark/run")
def run_benchmark(
    count: int = Query(10000, ge=100, le=1000000),
    chunk_size: int = Query(5000, ge=500, le=50000)
):
    """
    High-volume stress test and benchmarking endpoint.
    Streams up to 1,000,000 multi-vendor logs with bounded O(1) RAM.
    """
    from backend.processing.benchmark import generate_benchmark_stream
    stream = generate_benchmark_stream(count=count)
    summary = engine.process_batch(stream, chunk_size=chunk_size)
    return summary


@app.post("/api/system/clear")
@app.post("/api/demo/reset")
def clear_database_storage():
    """Clear database storage for maintenance or fresh ingestion."""
    store.clear_database()
    return {"message": "Database storage cleared successfully."}


@app.get("/api/events")
def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None,
    severity: Optional[str] = None,
    device_type: Optional[str] = None,
    vendor: Optional[str] = None
):
    """Event Explorer endpoint: searchable, filterable, paginated normalized events."""
    events, total = store.query_events(
        page=page,
        page_size=page_size,
        search=search,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        action=action,
        severity=severity,
        device_type=device_type,
        vendor=vendor
    )
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": (total + page_size - 1) // page_size if total > 0 else 0,
        "events": events
    }


@app.get("/api/events/{event_id}")
def get_event_detail(event_id: str):
    """Retrieve complete event record for side-by-side traceability and forensic audit."""
    event = store.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")
    return event


@app.get("/api/analytics")
def get_analytics():
    """Retrieve operational statistics, top talkers, actions, and protocol distributions."""
    return store.get_analytics()


@app.get("/api/failed")
def get_failed_events(limit: int = Query(50, ge=1, le=500)):
    """Retrieve quarantined failed events with error rationale."""
    return {
        "failed_events": store.get_failed_events(limit=limit)
    }


@app.get("/api/export")
def export_dataset(
    format: str = Query("json", pattern="^(json|jsonl|csv|failed_csv)$"),
    limit: int = Query(50000, ge=1, le=100000)
):
    """Download standardized normalized events for SIEM, Data Lake, or ML ingestion."""
    if format == "failed_csv":
        failed = store.get_failed_events(limit=limit)
        content = exporter.export_failed_csv(failed)
        return Response(content=content, media_type="text/csv", headers={
            "Content-Disposition": "attachment; filename=logforge_quarantined_failed.csv"
        })

    events = store.get_all_for_export(limit=limit)

    if format == "jsonl":
        content = exporter.export_jsonl(events)
        return Response(content=content, media_type="application/x-ndjson", headers={
            "Content-Disposition": "attachment; filename=logforge_normalized.jsonl"
        })
    elif format == "csv":
        content = exporter.export_csv(events)
        return Response(content=content, media_type="text/csv", headers={
            "Content-Disposition": "attachment; filename=logforge_normalized.csv"
        })
    else:
        content = exporter.export_json(events)
        return Response(content=content, media_type="application/json", headers={
            "Content-Disposition": "attachment; filename=logforge_normalized.json"
        })
