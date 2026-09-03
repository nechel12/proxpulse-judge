"""Pure logic of proxpulse-judge: no I/O, fully unit-testable."""
from __future__ import annotations

import hashlib

# Fixed tamper-check content. Never change bytes without bumping CONTENT_VERSION,
# otherwise checkers comparing against old baseline will see "modified".
CONTENT_VERSION = 1
FIXED_CONTENT = (
    b'{"proxpulse":"judge","v":1,'
    b'"payload":"0123456789abcdef0123456789abcdef0123456789abcdef"}'
)
CONTENT_SHA256 = hashlib.sha256(FIXED_CONTENT).hexdigest()

# Headers a reverse proxy (Caddy/nginx) adds itself. They must NOT be treated
# as proxy telltales, otherwise every check behind a reverse proxy
# would look "anonymous".
INFRA_HEADERS = frozenset({
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-ssl",
    "x-real-port",
})


def split_xff(value: str | None) -> list[str]:
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


def client_ip(xff: str | None, socket_ip: str, trust_proxy: bool) -> str:
    """Resolve the real client IP (= proxy exit IP when checked via proxy).

    Caddy appends the client address to the END of X-Forwarded-For,
    so with TRUST_PROXY=1 the last entry is authoritative.
    """
    if trust_proxy:
        chain = split_xff(xff)
        if chain:
            return chain[-1]
    return socket_ip


def forwarded_chain(xff: str | None, client: str, trust_proxy: bool) -> list[str]:
    """XFF entries added BEFORE our reverse proxy (i.e. by the checked proxy)."""
    if not trust_proxy:
        return split_xff(xff)
    chain = split_xff(xff)
    if chain and chain[-1] == client:
        chain = chain[:-1]
    return chain


def _is_telltale(name: str) -> bool:
    n = name.lower()
    if n in INFRA_HEADERS:
        return False
    if n in {
        "via",
        "forwarded",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "proxy-agent",
        "x-proxy-id",
        "x-real-ip",
    }:
        return True
    return n.startswith("proxy-") or n.startswith("x-proxy")


def anonymity_level(
    headers: dict[str, str],
    direct_ip: str | None = None,
) -> str:
    """elite | anonymous | transparent.

    `headers` — lowercased request headers as seen by judge,
    with the reverse-proxy-added last XFF entry already removed
    (see forwarded_chain). `direct_ip` — checker's own IP learned
    via a direct /ip call; without it leak detection is limited
    to multi-hop XFF chains.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    xff = lower.get("x-forwarded-for", "")
    chain = split_xff(xff)

    if direct_ip:
        if any(direct_ip == c or direct_ip in c for c in chain):
            return "transparent"
        if any(direct_ip in v for k, v in lower.items() if k != "x-forwarded-for"):
            return "transparent"
    if len(chain) > 1:
        # multi-hop chain without a known direct IP: something leaks hops
        return "transparent"
    if chain:
        return "anonymous"
    if any(_is_telltale(k) for k in lower):
        return "anonymous"
    return "elite"


HOSTING_KW = (
    "hosting", "host", "cloud", "vps", "dedicat", "datacenter",
    "data center", "colocation", "servers", "cdn", "compute",
    "bare metal", "virtual", "hypervisor",
)
# well-known hosters/clouds whose org names carry no generic keyword
HOSTING_VENDORS = (
    "hetzner", "ovh", "digitalocean", "amazon", "aws", "google",
    "microsoft", "azure", "cloudflare", "contabo", "aeza", "scaleway",
    "vultr", "linode", "leaseweb", "selectel", "timeweb", "beget",
    "alibaba", "tencent", "oracle cloud", "ibm cloud", "yandex cloud",
)
MOBILE_KW = ("mobile", "cellular", "wireless", "mobility", "gsm", " lte", "5g ")
RESIDENTIAL_KW = (
    "dynamic", "residential", "broadband", "dsl", "cable", "fiber",
    "ftth", " fttb", "pool", "retail", "subscriber",
)
BUSINESS_KW = (
    "ltd", "llc", "inc", "gmbh", "corp", "bank", "university",
    "government", "enterprise", "airline", "hotel",
)


def _hits(text: str, keywords: tuple[str, ...]) -> list[str]:
    t = f" {text.lower()} "
    return [k.strip() for k in keywords if k in t]


def classify_ip(
    org: str | None = None,
    asn_org: str | None = None,
    rdns: str | None = None,
) -> tuple[str, dict]:
    """Heuristic IP type. Returns (type, signals).

    Local data can't prove residential-vs-business the way paid
    ASN DBs do — the `signals` dict exposes WHY, so callers
    (and humans) can judge.
    """
    hay_org = f"{org or ''} {asn_org or ''}"
    hay_all = f"{hay_org} {rdns or ''}"
    hosting_kw = _hits(hay_org, HOSTING_KW)
    hosting_vendor = [v for v in HOSTING_VENDORS if v in hay_org.lower()]
    signals: dict = {
        "org": org,
        "asn_org": asn_org,
        "rdns": rdns,
        "hosting_kw": hosting_kw,
        "hosting_vendor": hosting_vendor,
        "mobile_kw": _hits(hay_all, MOBILE_KW),
        "residential_kw": _hits(hay_all, RESIDENTIAL_KW),
        "business_kw": _hits(hay_org, BUSINESS_KW),
    }
    if signals["mobile_kw"]:
        return "mobile", signals
    if hosting_kw or hosting_vendor:
        return "datacenter", signals
    if signals["business_kw"]:
        return "business", signals
    if signals["residential_kw"]:
        return "residential", signals
    if hay_org.strip():
        return "residential", {**signals, "note": "default: ordinary ISP"}
    return "unknown", signals
