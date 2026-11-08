# Signed answers

**English** | [Русский](signing.ru.md)

Anonymity can only be judged over plain HTTP: inside an HTTPS tunnel the
proxy cannot add headers. Over HTTP it could also rewrite the answer, for
example to claim `elite`. So every successful (`200`) `/judge` answer carries
an Ed25519 signature in `X-Judge-Signature` (base64) and the key id in
`X-Judge-Key-Id`. The signed message is

```text
proxpulse-judge-v1\n<nonce>\n<direct_ip>\n<response body>
```

with the `nonce` (8–64 characters of `A-Z a-z 0-9 _ -`, otherwise ignored)
and `direct_ip` query values after URL decoding; absent values are empty, and a
`direct_ip` containing a line feed counts as absent. ProxPulse sends a random
nonce for every checked proxy and fetches `/key` directly, not through a proxy,
so the checked proxy cannot swap the key, and an answer it rewrites or replays
fails verification.

Signatures matter only where `/judge` answers plain HTTP. The Caddy and nginx
examples serve `/judge`, `/content`, `/headers`, and `/ip` over plain HTTP on
port 80 and redirect everything else, `/key` included, to HTTPS. Render
redirects all HTTP to HTTPS, which hides the request from the judge, so
ProxPulse gets no anonymity verdict from it. (Before checker 0.6.1, its
HTTP-only mode reported one from the HTTPS answer, usually a false `elite`
whose signature still verified.) Signatures need judge 0.6.1 or newer; an older
judge answers `/key` with `404` and is treated as unsigned.

The key is only as trustworthy as the channel that delivered it. Over HTTPS,
TLS authenticates it. Over plain HTTP, a direct request only keeps out a checked
proxy that is not also on the direct path: anyone on that path (local network,
ISP, VPN) can substitute the key and forge answers, and a client that falls back
from HTTPS to HTTP can be forced onto it. Serve `/key` over HTTPS, and pin a
fixed key in the client when that is not enough. ProxPulse falls back to HTTP,
then shows a note saying so (for a key and for a `404` alike), follows no
redirects for `/key`, and does not pin the key. From checker 0.6.1 on, when
`/key` gets no clear answer it reports no integrity result rather than `ok`. A
`404` means an unsigned judge, whose answers it only compares by content hash,
which does not detect a rewritten verdict.

By default the key is generated at startup and kept only in memory, so it
changes on every restart. A client should fetch `/key` for every run and, after
a failed verification, fetch it once more and verify again, because the judge
may have restarted. It should not act on `X-Judge-Key-Id` alone: the header is
not signed and the proxy controls it. ProxPulse does this once per run from
checker 0.6.1 on; in older checkers a restart during a run marks the rest of that
run as modified and drops its anonymity verdicts.

Set `SIGNING_KEY` to keep one key across restarts or to pin it, and always when
several replicas sit behind one address, since each would otherwise sign with
its own key:

```sh
openssl rand -base64 32   # any 32 random bytes: put the output in SIGNING_KEY
```

The public key is derived from it. Keep the seed secret; a new seed changes
the key. Clients that fetch `/key` pick it up at their next run; a client that
pinned the key must be updated.
