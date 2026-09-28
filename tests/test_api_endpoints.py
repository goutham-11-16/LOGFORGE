"""Integration tests for LOGFORGE FastAPI REST endpoints."""
from fastapi.testclient import TestClient
from backend.api.app import app

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["parsers_loaded"] >= 6


def test_parsers_endpoint():
    res = client.get("/api/parsers")
    assert res.status_code == 200
    data = res.json()
    formats = [p["format"] for p in data["parsers"]]
    assert "SYSLOG" in formats
    assert "CEF" in formats
    assert "LEEF" in formats
    assert "JSON" in formats


def test_ingest_paste_and_explorer():
    raw_log = "<14>1 2026-09-28T14:50:00Z fw01 TRAFFIC - - - src=192.168.10.50 dst=1.1.1.1 sport=44332 dport=53 proto=udp action=allow"
    res = client.post("/api/ingest/paste", data={"raw_logs": raw_log})
    assert res.status_code == 200
    summary = res.json()
    assert summary["normalized_count"] == 1

    # Verify searchable in explorer
    res_search = client.get("/api/events?search=192.168.10.50")
    assert res_search.status_code == 200
    events_data = res_search.json()
    assert events_data["total"] >= 1
    found = events_data["events"][0]
    assert found["network"]["source_ip"] == "192.168.10.50"
    assert found["raw_event"] == raw_log


def test_demo_run_endpoint():
    res = client.post("/api/demo/run")
    assert res.status_code == 200
    summary = res.json()
    assert summary["total_events"] > 5000
    assert summary["normalized_count"] > 5000
    assert summary["events_per_second"] > 1000

    # Analytics check
    res_analytics = client.get("/api/analytics")
    assert res_analytics.status_code == 200
    analytics = res_analytics.json()
    assert analytics["total_events"] > 5000
    assert len(analytics["top_source_ips"]) > 0
    assert len(analytics["actions"]) > 0


def test_export_endpoints():
    res_json = client.get("/api/export?format=json")
    assert res_json.status_code == 200

    res_jsonl = client.get("/api/export?format=jsonl")
    assert res_jsonl.status_code == 200

    res_csv = client.get("/api/export?format=csv")
    assert res_csv.status_code == 200
    assert "source_ip" in res_csv.text
