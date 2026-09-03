"""API smoke tests: no DB files, no network (geo -> null, rest works)."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").json() == {"ok": True}


def test_generate_204():
    assert client.get("/generate_204").status_code == 204


def test_index_lists_endpoints():
    body = client.get("/").json()
    assert body["service"] == "proxpulse-judge"
    assert "GET /judge" in body["endpoints"]


def test_ip_testclient():
    body = client.get("/ip").json()
    assert "ip" in body and body["ip"]


def test_judge_without_db():
    body = client.get("/judge", params={"direct_ip": "1.1.1.1"}).json()
    assert body["anonymity"] == "elite"
    assert body["content_sha256"] and len(body["content_sha256"]) == 64
    assert body["ip_type"] in ("unknown", "residential")


def test_judge_transparent_via_header():
    # proxy forwarded 1.1.1.1, exit 5.6.7.8 (Caddy would append it last)
    body = client.get(
        "/judge",
        params={"direct_ip": "1.1.1.1"},
        headers={"X-Forwarded-For": "1.1.1.1, 5.6.7.8"},
    ).json()
    assert body["ip"] == "5.6.7.8"
    assert body["anonymity"] == "transparent"


def test_content_stable():
    r1 = client.get("/content").content
    r2 = client.get("/content").content
    assert r1 == r2 and len(r1) > 32
