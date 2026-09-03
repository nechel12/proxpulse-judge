"""Unit tests: pure logic, no DB, no network."""
from app.logic import (
    CONTENT_SHA256,
    FIXED_CONTENT,
    anonymity_level,
    classify_ip,
    client_ip,
    forwarded_chain,
)
import hashlib


def test_content_hash_stable():
    assert hashlib.sha256(FIXED_CONTENT).hexdigest() == CONTENT_SHA256
    assert len(FIXED_CONTENT) > 32


def test_client_ip_direct():
    assert client_ip(None, "9.9.9.9", False) == "9.9.9.9"
    assert client_ip(None, "9.9.9.9", True) == "9.9.9.9"


def test_client_ip_behind_caddy_takes_last():
    # proxy forwarded 1.2.3.4, Caddy appended exit 5.6.7.8
    assert client_ip("1.2.3.4, 5.6.7.8", "10.0.0.1", True) == "5.6.7.8"


def test_chain_strips_caddy_entry():
    assert forwarded_chain("1.2.3.4, 5.6.7.8", "5.6.7.8", True) == ["1.2.3.4"]
    assert forwarded_chain("5.6.7.8", "5.6.7.8", True) == []
    assert forwarded_chain("1.2.3.4", "9.9.9.9", False) == ["1.2.3.4"]


def test_elite_direct_behind_caddy():
    # Caddy added XFF with exit IP only; chain stripped -> elite
    assert anonymity_level({"x-forwarded-for": ""}, direct_ip="1.1.1.1") == "elite"
    assert anonymity_level({"user-agent": "x"}, direct_ip=None) == "elite"


def test_transparent_leak():
    h = {"x-forwarded-for": "1.1.1.1", "user-agent": "x"}
    assert anonymity_level(h, direct_ip="1.1.1.1") == "transparent"


def test_anonymous_forwarded_no_leak():
    h = {"x-forwarded-for": "9.9.9.9", "user-agent": "x"}
    assert anonymity_level(h, direct_ip="1.1.1.1") == "anonymous"


def test_anonymous_via():
    assert anonymity_level({"via": "1.0 proxy"}, direct_ip="1.1.1.1") == "anonymous"


def test_infra_headers_ignored():
    h = {"x-forwarded-proto": "https", "x-forwarded-host": "check.x"}
    assert anonymity_level(h, direct_ip="1.1.1.1") == "elite"


def test_classify_datacenter():
    t, s = classify_ip(org="Hetzner Online GmbH")
    assert t == "datacenter"
    assert s["hosting_kw"] or s["hosting_vendor"]


def test_classify_mobile():
    t, _ = classify_ip(org="Mobile TeleSystems PJSC")
    assert t == "mobile"


def test_classify_residential_default():
    t, _ = classify_ip(org="Rostelecom")
    assert t == "residential"


def test_classify_unknown():
    t, _ = classify_ip()
    assert t == "unknown"
