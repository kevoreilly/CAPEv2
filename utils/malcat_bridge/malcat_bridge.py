#!/usr/bin/env python3
"""
malcat_bridge.py - a secure HTTP API bridge to Malcat.

Runs *inside the Malcat venv* (where `import malcat` works) and exposes selected
Malcat features over the network so other systems (e.g. CAPE) can use them
without importing malcat into their own environment. Stdlib-only: it adds NO
packages to the malcat venv, so it can't conflict with Malcat's requirements.

Security model:
  * Clients authenticate with a bridge API key (X-API-Key header). Keys are
    stored HASHED in the config; the plaintext is shown once at generation.
  * The Malcat *license* lives only in the bridge config / env - clients never
    send or see it. This decouples CAPE from Malcat hosting.
  * Optional HTTPS (supply --tls-cert/--tls-key, or generate a self-signed pair
    with `gencert`). In production put it behind nginx; the built-in TLS is for
    getting a secure channel up quickly.
  * Binds to 127.0.0.1 by default; exposing on 0.0.0.0 without TLS warns loudly.

CLI:
    python malcat_bridge.py genkey            # create an API key (prints once)
    python malcat_bridge.py setlicense KEY    # store the Malcat license
    python malcat_bridge.py gencert           # self-signed cert via openssl
    python malcat_bridge.py serve --host 127.0.0.1 --port 8090 \
                                  [--tls-cert cert.pem --tls-key key.pem]

Endpoints:
    GET  /health              (no auth) -> {status, malcat_version, activated}
    GET  /v1/quota            (auth)    -> last-known online quota
    POST /v1/analyze          (auth)    -> run requested features on a sample
        body: raw file bytes (application/octet-stream)
        query: features=kesakode,capa,anomalies,yara,constants,info
               kesakode_mode=online|offline|auto
               filetype_force=PE|ELF   (optional)
               sha256=...              (optional; server recomputes anyway)
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOG = logging.getLogger("malcat_bridge")

DEFAULT_CONFIG = os.environ.get(
    "MALCAT_BRIDGE_CONFIG", os.path.expanduser("~/.malcat_bridge/config.json")
)

ALL_FEATURES = {"kesakode", "capa", "anomalies", "yara", "constants", "info"}

# Serializes malcat.analyse() calls (not thread-safe). BoundedSemaphore lets us
# raise the count later if we ever run multiple malcat workers in one process.
ANALYZE_SEM = threading.BoundedSemaphore(1)

# Pluggable analysis backend - real malcat by default; a fake can be injected
# for transport/auth testing without malcat present.
_BACKEND = None

# Last-seen online quota, updated after each online kesakode lookup.
_LAST_QUOTA = {"left": None, "total": None, "at": None}
_QUOTA_LOCK = threading.Lock()


class AnalysisCache:
    """Caches a completed Malcat analysis (and per-feature extractions) by
    sha256 so one uploaded sample is analysed ONCE even when CAPE calls the
    bridge separately for kesakode, then anomalies, then capa. Also caches the
    online kesakode result so repeat online requests for the same sample do NOT
    spend another quota token.

    In-memory with a TTL and an LRU size cap. Kept behind this small interface
    (get/get_or_analyse/store_feature/store_kesakode) so it can later be swapped
    for a shared store (e.g. Redis) when multiple bridges sit behind a load
    balancer - without touching run_analysis. Access is serialised by
    ANALYZE_SEM in run_analysis, so this class itself needs no extra locking.
    """

    def __init__(self, max_entries=16, ttl=600):
        self.max_entries = max(1, int(max_entries))
        self.ttl = int(ttl)
        self._store = {}          # sha256 -> entry dict
        self._order = []          # sha256, LRU (oldest first)

    def _evict_expired(self):
        if self.ttl <= 0:
            return
        now = time.time()
        for sha in list(self._store.keys()):
            if now - self._store[sha]["ts"] > self.ttl:
                self._drop(sha)

    def _drop(self, sha):
        self._store.pop(sha, None)
        if sha in self._order:
            self._order.remove(sha)

    def _touch(self, sha):
        if sha in self._order:
            self._order.remove(sha)
        self._order.append(sha)

    def get(self, sha):
        self._evict_expired()
        entry = self._store.get(sha)
        if entry is not None:
            self._touch(sha)
        return entry

    def new_entry(self, sha, analysis):
        entry = {"analysis": analysis, "ts": time.time(),
                 "extracted": {}, "kesakode": {}}
        self._store[sha] = entry
        self._touch(sha)
        while len(self._order) > self.max_entries:
            oldest = self._order[0]
            self._drop(oldest)
        return entry


# Set from config in cmd_serve; None disables caching.
_CACHE = None


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
def load_config(path):
    if not os.path.isfile(path):
        return {"api_key_hashes": [], "malcat_license": "", "max_upload_mb": 100,
                "kesakode_default_mode": "online", "workers": 1,
                "cache_max_entries": 16, "cache_ttl_seconds": 600}
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    cfg.setdefault("api_key_hashes", [])
    cfg.setdefault("malcat_license", "")
    cfg.setdefault("max_upload_mb", 100)
    cfg.setdefault("kesakode_default_mode", "online")
    cfg.setdefault("workers", 1)
    cfg.setdefault("cache_max_entries", 16)
    cfg.setdefault("cache_ttl_seconds", 600)
    return cfg


def save_config(path, cfg):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _hash_key(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def check_api_key(cfg, presented):
    if not presented:
        return False
    ph = _hash_key(presented)
    ok = False
    for stored in cfg.get("api_key_hashes", []):
        # constant-time compare against each stored hash
        if hmac.compare_digest(ph, stored):
            ok = True
    return ok


def resolve_license(cfg):
    return os.environ.get("MALCAT_BRIDGE_LICENSE") or cfg.get("malcat_license") or ""


# --------------------------------------------------------------------------
# Malcat analysis backend
# --------------------------------------------------------------------------
def _build_options(features, filetype_force):
    """Only compute what the caller asked for. Kesakode needs functions,
    strings, constants and entropy (entropy also yields md5/sha1/sha256), so
    those always stay on. invalidate_cache=False keeps Malcat's internal DBs
    resident between calls in the warm process.

    CAPA is special: it is verified to work only on Malcat's full default
    pipeline (capa.run() yields matches with nothing disabled). So when capa is
    requested we disable NOTHING. When capa is NOT requested we use a lean
    profile for the fast kesakode path."""
    opts = {"invalidate_cache": False}
    if "capa" in features:
        # CAPA is proven to work only on the full default pipeline (verified:
        # capa.run() yields matches with nothing disabled). Disabling scanners
        # around it is untested and risky, so when capa is requested we disable
        # NOTHING and let Malcat run its default passes.
        pass
    else:
        # Lean, fast path for the kesakode/yara/anomalies-only case. Kesakode
        # needs functions/strings/constants + entropy (kept); toggle the two
        # independent scanners by request and drop passes nothing here uses.
        opts["sign_disable"] = "yara" not in features
        opts["anom_disable"] = "anomalies" not in features
        opts["subf_disable"] = True     # carving
        opts["flirt_disable"] = True    # FLIRT library sigs
        opts["dbg_disable"] = True      # debug metadata
        opts["xref_disable"] = True     # xref graph
    if filetype_force:
        opts["filetype_force"] = filetype_force
    return opts


def _analyse_with_opts(malcat, path, opts):
    """analyse() honouring options, with the TypeError fallback some builds need
    for the filetype kwarg form."""
    try:
        return malcat.analyse(path, options=opts)
    except TypeError:
        ft = opts.get("filetype_force")
        if ft:
            return malcat.analyse(path, filetype=ft)
        return malcat.analyse(path)


def _malcat_analyse(data_bytes, features, filetype_force):
    """Write bytes to a temp file, analyse with only the requested work enabled,
    applying the empty-file.type fallback proven in CAPE_Kesakode.py. Returns
    (analysis, temp_path)."""
    import malcat

    fd, tmp = tempfile.mkstemp(prefix="malcat_bridge_")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data_bytes)
        os.chmod(tmp, 0o600)

        opts = _build_options(features, filetype_force)
        analysis = _analyse_with_opts(malcat, tmp, opts)

        ftype = getattr(analysis.file, "type", "") or ""
        if not ftype and not filetype_force:
            # Auto-detect empty (common for .NET / stripped CAPE dumps): re-run
            # forcing the container format from magic bytes.
            magic = data_bytes[:4]
            if magic.startswith(b"\x7fELF"):
                opts["filetype_force"] = "ELF"
            else:
                opts["filetype_force"] = "PE"   # MZ or unknown -> PE
            analysis = _analyse_with_opts(malcat, tmp, opts)
        return analysis, tmp
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _extract_kesakode(analysis, mode, license, quota_reserve=0):
    out = {"mode": mode, "verdict": {}, "counts": {}, "quota_left": None,
           "quota_total": None, "used_online": False}
    kk = getattr(analysis, "kesakode", None)

    def counts(obj):
        return {
            "malware": getattr(obj, "count_malware", None),
            "library": getattr(obj, "count_library", None),
            "clean": getattr(obj, "count_clean", None),
            "unknown": getattr(obj, "count_unknown", None),
        }

    offline_verdict = {}
    if kk is not None:
        try:
            offline_verdict = dict(getattr(kk, "verdict", {}) or {})
            out["counts"] = counts(kk)
        except Exception:
            pass

    if mode == "offline":
        out["verdict"] = offline_verdict
        return out

    if mode == "auto" and offline_verdict:
        out["verdict"] = offline_verdict
        return out

    # online (either mode == online, or auto with empty offline)
    if not license:
        out["error"] = "online kesakode requested but no license configured on bridge"
        out["verdict"] = offline_verdict
        return out

    # Quota floor: refuse online lookups once the last-seen remaining quota is
    # at/below the caller's reserve, so a busy pipeline can't drain the month.
    # The first lookup (quota unknown) always proceeds; subsequent ones are
    # gated by the quota_left reported on the previous online result.
    if quota_reserve and quota_reserve > 0:
        with _QUOTA_LOCK:
            last_left = _LAST_QUOTA.get("left")
        if last_left is not None and last_left <= quota_reserve:
            out["skipped"] = "quota_floor"
            out["error"] = f"online lookup skipped: quota {last_left} <= reserve {quota_reserve}"
            out["verdict"] = offline_verdict
            with _QUOTA_LOCK:
                out["quota_left"] = _LAST_QUOTA.get("left")
                out["quota_total"] = _LAST_QUOTA.get("total")
            return out
    try:
        if hasattr(analysis, "kesakode_lookup"):
            res = analysis.kesakode_lookup(license)
        else:
            res = analysis.kesakode.online_lookup(license, ssl_verify=True)
        out["verdict"] = dict(getattr(res, "verdict", {}) or {})
        out["counts"] = counts(res)
        out["quota_left"] = getattr(res, "quota_left", None)
        out["quota_total"] = getattr(res, "quota_total", None)
        out["used_online"] = True
        with _QUOTA_LOCK:
            _LAST_QUOTA["left"] = out["quota_left"]
            _LAST_QUOTA["total"] = out["quota_total"]
            _LAST_QUOTA["at"] = time.time()
    except Exception as err:
        out["error"] = f"{type(err).__name__}: {err}"
        out["verdict"] = offline_verdict
    return out


def _capa_term(obj):
    """CAPA attack/mbc entries are objects (CapaAttackTechnique/CapaMbcBehavior),
    not strings. Convert to a JSON-safe form: prefer structured fields if the
    object exposes them, else fall back to str()."""
    if isinstance(obj, str):
        return obj
    d = {}
    for attr in ("id", "tid", "technique", "tactic", "subtechnique",
                 "objective", "behavior", "method", "name", "parts"):
        if hasattr(obj, attr):
            try:
                val = getattr(obj, attr)
            except Exception:
                continue
            if val is None:
                continue
            # nested lists/objects -> stringify their parts
            if isinstance(val, (list, tuple)):
                val = [x if isinstance(x, (str, int, float, bool)) else str(x) for x in val]
            elif not isinstance(val, (str, int, float, bool)):
                val = str(val)
            d[attr] = val
    return d or str(obj)


def _extract_capa(analysis):
    caps = []
    # analysis.capa returns a fresh object per access; results populated by run()
    # are only visible via a FRESH access, so we must NOT bind it to a local and
    # reuse that reference. Access analysis.capa fresh for run() and iteration -
    # exactly as the working standalone script does. (Binding once returns 0.)
    if getattr(analysis, "capa", None) is None:
        return caps
    analysis.capa.run()  # CAPA is not triggered by default
    for rule in analysis.capa:
        if getattr(rule, "matches", False):
            caps.append({
                "name": getattr(rule, "name", "Unknown"),
                "namespace": getattr(rule, "namespace", "Unknown"),
                "attack": [_capa_term(t) for t in (getattr(rule, "attack", []) or [])],
                "mbc": [_capa_term(t) for t in (getattr(rule, "mbc", []) or [])],
            })
    return caps


def _extract_anomalies(analysis):
    fns = getattr(analysis, "fns", None)
    can_find = fns is not None and hasattr(fns, "find")
    res = []
    for anom in getattr(analysis, "anomalies", []) or []:
        locs = []
        for addr, size in getattr(anom, "locations", []) or []:
            entry = {"address": hex(addr), "size": size}
            if can_find:
                # Resolve which function this location falls in, with the offset
                # into it (e.g. "sub_401000+0x2a") - the depth we want for triage.
                try:
                    fn = fns.find(addr)
                    if fn is not None and hasattr(fn, "address") and hasattr(fn, "name"):
                        offset = addr - fn.address
                        if offset >= 0:
                            entry["function"] = fn.name
                            entry["function_offset"] = hex(offset)
                except Exception:
                    pass
            locs.append(entry)
        res.append({
            "label": getattr(anom, "label", getattr(anom, "name", "Unknown")),
            "category": getattr(anom, "category", "unknown"),
            "locations": locs,
        })
    return res


def run_analysis(data_bytes, features, filetype_force, kesakode_mode, license, quota_reserve=0):
    """Backend entry point. The ANALYZE_SEM (default 1) serialises ALL analysis
    work - malcat.analyse() is not thread-safe, so nothing that performs an
    analysis, real or injected, may run concurrently beyond the configured
    worker count.

    A sample is analysed ONCE per sha256 (cached), so separate CAPE calls for
    kesakode / anomalies / capa reuse a single Malcat analysis, and repeat
    online kesakode requests reuse the cached verdict without spending another
    quota token."""
    with ANALYZE_SEM:
        if _BACKEND is not None:
            return _BACKEND(data_bytes, features, filetype_force, kesakode_mode, license)

        sha256 = hashlib.sha256(data_bytes).hexdigest()
        result = {"sha256": sha256, "features": {}, "errors": {}}
        try:
            import malcat
            result["malcat_version"] = malcat.version()
        except Exception:
            result["malcat_version"] = None

        # -- one analysis per sha256 (cache) ------------------------------
        entry = _CACHE.get(sha256) if _CACHE is not None else None
        tmp = None
        if entry is None:
            t0 = time.time()
            analysis, tmp = _malcat_analyse(data_bytes, features, filetype_force)
            result["analyse_seconds"] = round(time.time() - t0, 3)
            result["cached"] = False
            if _CACHE is not None:
                entry = _CACHE.new_entry(sha256, analysis)
            else:
                entry = {"analysis": analysis, "extracted": {}, "kesakode": {}}
        else:
            analysis = entry["analysis"]
            result["analyse_seconds"] = 0.0
            result["cached"] = True

        try:
            f = getattr(analysis, "file", None)
            result["file"] = {
                "type": getattr(f, "type", "") or "",
                "architecture": str(getattr(analysis, "architecture", "") or ""),
                "size": getattr(f, "size", len(data_bytes)),
            }
            if "info" in features:
                if "info" not in entry["extracted"]:
                    entry["extracted"]["info"] = {
                        "functions": len(getattr(analysis, "fns", []) or []),
                        "strings": len(getattr(analysis, "strings", []) or []),
                        "constants": len(getattr(analysis, "constants", []) or []),
                        "carved": len(getattr(analysis, "carved", []) or []),
                    }
                result["counts"] = entry["extracted"]["info"]

            for feat in features:
                try:
                    if feat == "kesakode":
                        result["features"]["kesakode"] = _kesakode_cached(
                            entry, analysis, kesakode_mode, license, quota_reserve)
                    elif feat == "info":
                        pass  # handled above
                    elif feat in entry["extracted"]:
                        result["features"][feat] = entry["extracted"][feat]
                    elif feat == "capa":
                        entry["extracted"]["capa"] = _extract_capa(analysis)
                        result["features"]["capa"] = entry["extracted"]["capa"]
                    elif feat == "anomalies":
                        entry["extracted"]["anomalies"] = _extract_anomalies(analysis)
                        result["features"]["anomalies"] = entry["extracted"]["anomalies"]
                    elif feat == "yara":
                        entry["extracted"]["yara"] = [
                            s.name for s in getattr(analysis, "sigs", []) or []
                            if getattr(s, "matches", False)]
                        result["features"]["yara"] = entry["extracted"]["yara"]
                    elif feat == "constants":
                        entry["extracted"]["constants"] = [
                            getattr(c, "name", str(c))
                            for c in getattr(analysis, "constants", []) or []]
                        result["features"]["constants"] = entry["extracted"]["constants"]
                except Exception as err:
                    result["errors"][feat] = f"{type(err).__name__}: {err}"
        finally:
            # Only delete the temp file when we are NOT caching the analysis;
            # if cached, keep it until the entry is evicted (some Malcat objects
            # may lazily reference the mapped file).
            if tmp is not None and _CACHE is None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            elif tmp is not None:
                entry["tmp"] = tmp  # tracked for cleanup on eviction
    return result


def _kesakode_cached(entry, analysis, mode, license, quota_reserve):
    """Kesakode extraction with token-preserving cache: an online verdict for a
    sample is fetched at most once; repeat online requests reuse it. Offline is
    cheap but also cached for consistency."""
    kc = entry["kesakode"]
    want_online = mode in ("online", "auto")
    if want_online and kc.get("online") is not None:
        return kc["online"]
    if mode == "offline" and kc.get("offline") is not None:
        return kc["offline"]

    out = _extract_kesakode(analysis, mode, license, quota_reserve=quota_reserve)
    # Cache by what actually happened: an online result (or a quota-skip) under
    # 'online' so we don't retry; a pure offline read under 'offline'.
    if out.get("used_online") or out.get("skipped") == "quota_floor":
        kc["online"] = out
    elif mode == "offline":
        kc["offline"] = out
    return out


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "malcat-bridge/1.0"
    config = {}

    def log_message(self, fmt, *args):
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, code, obj):
        # default=str ensures a single unexpected non-serializable object degrades
        # to its string form instead of crashing the whole response.
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return check_api_key(self.config, self.headers.get("X-API-Key", ""))

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            info = {"status": "ok"}
            try:
                import malcat
                info["malcat_version"] = malcat.version()
                info["activated"] = bool(getattr(malcat.env, "is_activated", False))
            except Exception:
                info["malcat_version"] = None
                info["activated"] = None
            return self._send(200, info)
        if path == "/v1/quota":
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            with _QUOTA_LOCK:
                return self._send(200, {"quota": dict(_LAST_QUOTA),
                                        "note": "last-seen online quota; updated on online lookups"})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/v1/analyze":
            return self._send(404, {"error": "not found"})
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})

        q = parse_qs(parsed.query)
        feats_raw = (q.get("features", ["kesakode"])[0] or "kesakode")
        features = {f.strip().lower() for f in feats_raw.split(",") if f.strip()}
        bad = features - ALL_FEATURES
        if bad:
            return self._send(400, {"error": f"unknown features: {sorted(bad)}",
                                    "known": sorted(ALL_FEATURES)})
        kesakode_mode = (q.get("kesakode_mode", [self.config.get("kesakode_default_mode", "online")])[0]
                         or "online").lower()
        if kesakode_mode not in ("online", "offline", "auto"):
            return self._send(400, {"error": "kesakode_mode must be online|offline|auto"})
        filetype_force = (q.get("filetype_force", [""])[0] or "").upper() or None
        try:
            quota_reserve = int(q.get("quota_reserve", ["0"])[0] or 0)
        except ValueError:
            quota_reserve = 0

        length = int(self.headers.get("Content-Length", 0) or 0)
        max_bytes = int(self.config.get("max_upload_mb", 100)) * 1024 * 1024
        if length <= 0:
            return self._send(400, {"error": "empty body; POST raw file bytes"})
        if length > max_bytes:
            return self._send(413, {"error": f"file too large (> {self.config['max_upload_mb']} MB)"})
        data = self.rfile.read(length)
        if len(data) != length:
            return self._send(400, {"error": "incomplete body"})

        license = resolve_license(self.config)
        try:
            result = run_analysis(data, features, filetype_force, kesakode_mode, license,
                                  quota_reserve=quota_reserve)
        except Exception as err:
            LOG.exception("analysis failed")
            return self._send(500, {"error": f"{type(err).__name__}: {err}"})
        return self._send(200, result)


# --------------------------------------------------------------------------
# CLI commands
# --------------------------------------------------------------------------
def cmd_genkey(args):
    cfg = load_config(args.config)
    key = "mbk_" + secrets.token_urlsafe(32)
    cfg["api_key_hashes"].append(_hash_key(key))
    save_config(args.config, cfg)
    print("New API key (store it now, it will NOT be shown again):\n")
    print("   " + key + "\n")
    print(f"Saved hash to {args.config}. Total keys: {len(cfg['api_key_hashes'])}")


def cmd_setlicense(args):
    cfg = load_config(args.config)
    cfg["malcat_license"] = args.license.strip()
    save_config(args.config, cfg)
    print(f"Malcat license stored in {args.config} (used for online kesakode).")


def cmd_gencert(args):
    cert = args.cert or "malcat_bridge_cert.pem"
    key = args.key or "malcat_bridge_key.pem"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", str(args.days),
             "-subj", f"/CN={args.cn}"],
            check=True)
        os.chmod(key, 0o600)
        print(f"Self-signed cert: {cert}\nPrivate key: {key}\n"
              f"Serve with: serve --tls-cert {cert} --tls-key {key}")
    except FileNotFoundError:
        print("openssl not found. Install it, or supply your own --tls-cert/--tls-key.")
        sys.exit(1)
    except subprocess.CalledProcessError as err:
        print("openssl failed:", err)
        sys.exit(1)


def cmd_serve(args):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    if not cfg["api_key_hashes"]:
        print("No API keys configured. Run: python malcat_bridge.py genkey")
        sys.exit(1)

    workers = int(args.workers or cfg.get("workers", 1))
    global ANALYZE_SEM
    ANALYZE_SEM = threading.BoundedSemaphore(max(1, workers))

    # Analysis cache: one Malcat analysis per sha256 reused across kesakode /
    # anomalies / capa calls, and online kesakode verdicts reused without
    # re-spending quota. cache_max_entries <= 0 disables it.
    global _CACHE
    cache_max = int(cfg.get("cache_max_entries", 16))
    cache_ttl = int(cfg.get("cache_ttl_seconds", 600))
    if cache_max > 0:
        _CACHE = AnalysisCache(max_entries=cache_max, ttl=cache_ttl)
        LOG.info("Analysis cache on (max_entries=%d, ttl=%ds).", cache_max, cache_ttl)
    else:
        _CACHE = None
        LOG.info("Analysis cache disabled.")

    if not args.fake_backend:
        try:
            import malcat
            malcat.setup()
            LOG.info("malcat %s ready (activated=%s)", malcat.version(),
                     getattr(malcat.env, "is_activated", "?"))
        except Exception as err:
            print("Could not import/setup malcat - run this in the malcat venv. Error:", err)
            sys.exit(1)
    else:
        global _BACKEND
        _BACKEND = _fake_backend
        LOG.warning("RUNNING WITH FAKE BACKEND (testing only, malcat not used)")

    Handler.config = cfg
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)

    scheme = "http"
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    elif args.host not in ("127.0.0.1", "localhost", "::1"):
        LOG.warning("Serving on %s WITHOUT TLS - put nginx in front or use --tls-cert/--tls-key",
                    args.host)

    LOG.info("Serving %s://%s:%d  (workers=%d, features=%s)",
             scheme, args.host, args.port, workers, ",".join(sorted(ALL_FEATURES)))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOG.info("shutting down")
        httpd.shutdown()


def _fake_backend(data_bytes, features, filetype_force, kesakode_mode, license):
    """Canned result for transport/auth testing without malcat."""
    sha = hashlib.sha256(data_bytes).hexdigest()
    out = {"sha256": sha, "malcat_version": "FAKE", "analyse_seconds": 0.01,
           "file": {"type": "PE", "architecture": "DOTNET", "size": len(data_bytes)},
           "features": {}, "errors": {}}
    if "info" in features:
        out["counts"] = {"functions": 123, "strings": 456, "constants": 5, "carved": 0}
    if "kesakode" in features:
        out["features"]["kesakode"] = {
            "mode": kesakode_mode, "used_online": kesakode_mode != "offline",
            "verdict": {"Kazuar": 100.0, "GIMMICK": 0.08},
            "counts": {"malware": 2, "library": 0, "clean": 0, "unknown": 10},
            "quota_left": 99, "quota_total": 100}
    if "capa" in features:
        out["features"]["capa"] = [{"name": "encrypt data using RC4",
                                    "namespace": "data-manipulation/encryption/rc4",
                                    "attack": ["T1027"], "mbc": []}]
    if "anomalies" in features:
        out["features"]["anomalies"] = [{"label": "entrypoint outside section",
                                         "category": "header", "locations": [{"address": "0x1000", "size": 4}]}]
    if "yara" in features:
        out["features"]["yara"] = ["Kazuar"]
    if "constants" in features:
        out["features"]["constants"] = ["RC4", "CRC32"]
    return out


EPILOG = """\
subcommands (each also has its own -h):

  genkey                     generate an API key (printed once, stored hashed)
  setlicense LICENSE         store the Malcat license (for online kesakode)
  gencert [--cert --key      make a self-signed TLS cert/key via openssl
           --days --cn]
  serve   --host H --port P  run the bridge
          [--tls-cert FILE --tls-key FILE]   enable HTTPS
          [--workers N]      concurrent malcat analyses (default 1)
          [--fake-backend]   testing only: canned results, no malcat

global:
  --config PATH              config file (default ~/.malcat_bridge/config.json
                             or $MALCAT_BRIDGE_CONFIG)

environment:
  MALCAT_BRIDGE_LICENSE      overrides the stored license
  MALCAT_BRIDGE_CONFIG       overrides the config path

examples:
  python malcat_bridge.py genkey
  python malcat_bridge.py setlicense XXXX-XXXX-XXXX-XXXX
  python malcat_bridge.py gencert
  python malcat_bridge.py serve --host 127.0.0.1 --port 8090 \\
      --tls-cert malcat_bridge_cert.pem --tls-key malcat_bridge_key.pem
  python malcat_bridge.py serve --host 0.0.0.0 --port 8090 \\
      --tls-cert cert.pem --tls-key key.pem   # prefer nginx in front
"""


def main():
    ap = argparse.ArgumentParser(
        description="Secure HTTP API bridge to Malcat (run inside the malcat venv).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="config file path")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="{genkey,setlicense,gencert,serve}")

    sub.add_parser("genkey", help="generate an API key")

    p_lic = sub.add_parser("setlicense", help="store the Malcat license")
    p_lic.add_argument("license")

    p_cert = sub.add_parser("gencert", help="generate a self-signed TLS cert (needs openssl)")
    p_cert.add_argument("--cert", default=None)
    p_cert.add_argument("--key", default=None)
    p_cert.add_argument("--days", type=int, default=365)
    p_cert.add_argument("--cn", default="malcat-bridge")

    p_serve = sub.add_parser("serve", help="run the bridge")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8090)
    p_serve.add_argument("--tls-cert", default=None)
    p_serve.add_argument("--tls-key", default=None)
    p_serve.add_argument("--workers", type=int, default=None,
                         help="concurrent malcat analyses (default 1; only raise if analyse() is proven safe)")
    p_serve.add_argument("--fake-backend", action="store_true",
                         help="testing only: serve canned results without malcat")

    args = ap.parse_args()
    if args.cmd == "genkey":
        cmd_genkey(args)
    elif args.cmd == "setlicense":
        cmd_setlicense(args)
    elif args.cmd == "gencert":
        cmd_gencert(args)
    elif args.cmd == "serve":
        cmd_serve(args)


if __name__ == "__main__":
    main()
