# Malcat bridge

A small, stdlib-only HTTP(S) service that exposes selected
[Malcat](https://malcat.fr) features (Kesakode code-similarity, CAPA, anomalies,
YARA, constants) over an authenticated network API, so CAPE can use them without
importing Malcat into its own environment.

**This service runs alongside Malcat — in Malcat's own Python venv — NOT in
CAPE's venv.** Malcat needs a specific Python version and its own
`requirements.txt`; keeping it behind an HTTP bridge decouples Malcat hosting
from CAPE (Malcat can live on the same host, another server, or in a
container) and keeps the Malcat license server-side. CAPE talks to it exactly
like it talks to an MCRIT server.

Files:

* `malcat_bridge.py` — the bridge service (stdlib only; runs in Malcat's venv).
* `malcat_client_cli.py` — a standalone CLI tester for the bridge (needs only
  `requests`; useful to confirm the bridge works before wiring up CAPE).

## 1. Install (on the Malcat host, in Malcat's venv)

Install Malcat's Python module into a venv as per Malcat's docs
(`install_api.py`), then copy `malcat_bridge.py` next to it. The bridge imports
only the Python standard library plus `malcat`, so there is nothing else to
install.

```bash
# in Malcat's venv, where `import malcat` works:
python malcat_bridge.py -h          # shows all subcommands + examples
```

Config lives at `~/.malcat_bridge/config.json` (override with
`$MALCAT_BRIDGE_CONFIG`). It stores the API-key **hashes** (never the plaintext)
and the Malcat license.

## 2. One-time setup

```bash
# 1. Generate an API key. It is printed ONCE - copy it now; only its hash is stored.
python malcat_bridge.py genkey

# 2. Store your Malcat license (used for online Kesakode lookups).
python malcat_bridge.py setlicense XXXX-XXXX-XXXX-XXXX
#    (or set $MALCAT_BRIDGE_LICENSE in the environment instead)

# 3. Optional: generate a self-signed TLS cert/key (needs openssl).
python malcat_bridge.py gencert
#    In production, prefer a real cert or put nginx in front.
```

## 3. Run

```bash
# localhost over HTTPS with the self-signed cert:
python malcat_bridge.py serve --host 127.0.0.1 --port 8090 \
    --tls-cert malcat_bridge_cert.pem --tls-key malcat_bridge_key.pem

# exposed on the network (put nginx/TLS in front for real deployments):
python malcat_bridge.py serve --host 0.0.0.0 --port 8090 \
    --tls-cert cert.pem --tls-key key.pem
```

Endpoints: `GET /health` (no auth), `GET /v1/quota` (auth), `POST /v1/analyze`
(auth; raw file bytes as the body, `features=` and `kesakode_mode=` as query
params). Auth is the `X-API-Key` header. `analyse()` calls are serialised
server-side (Malcat is one-at-a-time per process); scale out by running several
bridges and round-robining — that is a CAPE-side concern, the bridge stays
simple.

## 4. Test it (optional, before wiring CAPE)

From anywhere with `requests`:

```bash
# health
python malcat_client_cli.py --url https://HOST:8090 --insecure --health

# a full analysis (spends one online Kesakode token)
python malcat_client_cli.py --url https://HOST:8090 --api-key mbk_... --insecure \
    --features kesakode,capa,anomalies,yara,constants,info \
    --kesakode-mode online --json /path/to/unpacked_sample
```

`--insecure` skips TLS verification for a self-signed bridge cert.

## 5. Point CAPE at it

In CAPE's `conf/integrations.conf`, `[similarity]` section, set `kesakode = yes`
and the `kesakode_host` / `kesakode_apikey` / `kesakode_ssl_verify` values to
match this bridge. Anomalies and the Malcat CAPA override are configured in the
`[malcat]` section (and enabled in `conf/processing.conf [malcat]`). For a
self-signed bridge cert, set `kesakode_ssl_verify = no` (and `malcat_ssl_verify
= no`). See the comments in `integrations.conf` for the full option list.

## Notes

* Kesakode works on **unpacked** code (CAPE payloads / procdumps are ideal).
* Online Kesakode consumes a small monthly quota; the bridge enforces a quota
  floor (`quota_reserve`) and CAPE can defer online lookups to an on-demand
  button. Offline Kesakode (OEM headless build) has no quota.
* The bridge caches one Malcat analysis per sha256, so CAPE's separate calls for
  kesakode / anomalies / capa on the same artifact reuse a single analysis and a
  single online token.
