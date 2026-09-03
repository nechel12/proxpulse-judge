"""proxpulse-judge: self-hosted proxy-check backend.

One GET /judge replaces several third-party calls (ip-api, httpbin, ...):
it sees the proxy exit IP, resolves geo from LOCAL .mmdb files,
echoes headers for anonymity analysis and serves fixed content
for tamper checks.
"""
from __future__ import annotations

import asyncio
import os
import socket

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import ORJSONResponse

from . import geo as geo_mod
from .logic import (
    CONTENT_SHA256,
    CONTENT_VERSION,
    FIXED_CONTENT,
    anonymity_level,
    classify_ip,
    client_ip,
    forwarded_chain,
)

TRUST_PROXY = os.environ.get("TRUST_PROXY", "1") == "1"
RDNS_TIMEOUT = float(os.environ.get("RDNS_TIMEOUT", "1.5"))

app = FastAPI(
    title="proxpulse-judge",
    version="0.1.0",
    default_response_class=ORJSONResponse,
)

pool = geo_mod.init_pool()


def _socket_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "127.0.0.1"


def _headers_lower(request: Request) -> dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()}


def _self_ip(request: Request) -> str:
    return client_ip(
        request.headers.get("x-forwarded-for"),
        _socket_ip(request),
        TRUST_PROXY,
    )


async def _rdns(ip: str) -> str | None:
    try:
        name, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip), timeout=RDNS_TIMEOUT
        )
        return name
    except Exception:  # noqa: BLE001 - timeouts, NXDOMAIN, no resolver
        return None


@app.get("/")
async def index():
    return {
        "service": "proxpulse-judge",
        "version": "0.1.0",
        "trust_proxy": TRUST_PROXY,
        "geo_sources": pool.sources,
        "endpoints": [
            "GET /generate_204",
            "GET /ip",
            "GET /headers",
            "GET /geo",
            "GET /type",
            "GET /content",
            "GET /judge",
            "GET /healthz",
        ],
    }


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/generate_204", status_code=204)
async def generate_204():
    return Response(status_code=204)


@app.get("/ip")
async def ip(request: Request):
    return {"ip": _self_ip(request)}


@app.get("/headers")
async def headers(request: Request):
    me = _self_ip(request)
    raw = _headers_lower(request)
    chain = forwarded_chain(request.headers.get("x-forwarded-for"), me, TRUST_PROXY)
    visible = dict(raw)
    if TRUST_PROXY and "x-forwarded-for" in visible:
        # strip the entry our own reverse proxy appended
        visible["x-forwarded-for"] = ", ".join(chain) if chain else "(stripped)"
    return {"ip": me, "headers": visible, "xff_chain": chain}


@app.get("/geo")
async def geo(request: Request):
    me = _self_ip(request)
    data = pool.lookup(me)
    return {"ip": me, "geo": data, "source": pool.sources or None}


@app.get("/type")
async def ip_type(request: Request, rdns: int = Query(0)):
    me = _self_ip(request)
    data = pool.lookup(me)
    ptr = await _rdns(me) if rdns else None
    org = data.get("aso")
    t, signals = classify_ip(org=org, asn_org=None, rdns=ptr)
    return {"ip": me, "ip_type": t, "signals": signals}


@app.get("/content")
async def content():
    return Response(content=FIXED_CONTENT, media_type="application/json")


@app.get("/judge")
async def judge(
    request: Request,
    direct_ip: str | None = Query(None),
    rdns: int = Query(0),
):
    """All-in-one verdict for one proxy exit IP."""
    me = _self_ip(request)
    raw = _headers_lower(request)
    chain = forwarded_chain(request.headers.get("x-forwarded-for"), me, TRUST_PROXY)

    for_analysis = dict(raw)
    if TRUST_PROXY and "x-forwarded-for" in for_analysis:
        # our reverse proxy appended `me` last — remove it, the rest
        # (if any) was forwarded by the checked proxy
        for_analysis["x-forwarded-for"] = ", ".join(chain)

    level = anonymity_level(for_analysis, direct_ip=direct_ip)

    g = pool.lookup(me)
    ptr = await _rdns(me) if rdns else None
    t, signals = classify_ip(org=g.get("aso"), rdns=ptr)

    return {
        "ip": me,
        "headers": raw,
        "xff_chain": chain,
        "anonymity": level,
        "geo": g,
        "geo_source": pool.sources or None,
        "ip_type": t,
        "type_signals": signals,
        "content_version": CONTENT_VERSION,
        "content_sha256": CONTENT_SHA256,
    }
