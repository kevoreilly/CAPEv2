#!/usr/bin/env python3
"""
malcat_client_cli.py - standalone CLI tester for the Malcat bridge.

Talks to a running malcat_bridge over HTTP(S). Runs anywhere with `requests`.
Use it to test the bridge directly, independent of CAPE - especially to isolate
whether a problem is the bridge/transport or the CAPE-side engine wiring.

Examples:
    # health check (no auth)
    python3 malcat_client_cli.py --url https://127.0.0.1:8090 --insecure --health

    # last-seen online quota
    python3 malcat_client_cli.py --url https://127.0.0.1:8090 --api-key mbk_... --insecure --quota

    # KESAKODE ONLY, online - the exact path CAPE's engine uses (spends a token)
    python3 malcat_client_cli.py --url https://127.0.0.1:8090 --api-key mbk_... --insecure \
        --features kesakode --kesakode-mode online --json SAMPLE

    # kesakode offline (no token) if your OEM offline works
    python3 malcat_client_cli.py --url https://127.0.0.1:8090 --api-key mbk_... --insecure \
        --features kesakode --kesakode-mode offline --json SAMPLE

    # everything at once
    python3 malcat_client_cli.py --url https://127.0.0.1:8090 --api-key mbk_... --insecure \
        --features kesakode,capa,anomalies,yara,constants,info --kesakode-mode online SAMPLE
"""

import argparse
import json
import os
import sys

import requests

try:
    import urllib3
except ImportError:
    urllib3 = None


def health(url, insecure):
    r = requests.get(f"{url.rstrip('/')}/health", verify=not insecure, timeout=15)
    r.raise_for_status()
    return r.json()


def quota(url, api_key, insecure):
    r = requests.get(f"{url.rstrip('/')}/v1/quota",
                     headers={"X-API-Key": api_key}, verify=not insecure, timeout=15)
    r.raise_for_status()
    return r.json()


def analyze(url, api_key, sample_path, features, kesakode_mode, filetype_force,
            quota_reserve, insecure, timeout):
    with open(sample_path, "rb") as fh:
        data = fh.read()
    params = {"features": ",".join(features), "kesakode_mode": kesakode_mode}
    if filetype_force:
        params["filetype_force"] = filetype_force
    if quota_reserve:
        params["quota_reserve"] = int(quota_reserve)
    r = requests.post(
        f"{url.rstrip('/')}/v1/analyze",
        params=params,
        data=data,
        headers={"X-API-Key": api_key, "Content-Type": "application/octet-stream"},
        verify=not insecure,
        timeout=timeout,
    )
    if r.status_code >= 400:
        try:
            raise SystemExit(f"[{r.status_code}] {r.json()}")
        except ValueError:
            raise SystemExit(f"[{r.status_code}] {r.text}")
    return r.json()


def _term(t):
    if isinstance(t, dict):
        return t.get("id") or t.get("technique") or t.get("behavior") or t.get("name") or str(t)
    return str(t)


def _print_report(res):
    print(f"\nsha256      : {res.get('sha256')}")
    print(f"malcat      : {res.get('malcat_version')}   analyse: {res.get('analyse_seconds')}s"
          + (f"   (cached)" if res.get("cached") else ""))
    f = res.get("file", {})
    print(f"file        : type={f.get('type')!r} arch={f.get('architecture')} size={f.get('size')}")
    if res.get("counts"):
        c = res["counts"]
        print(f"artifacts   : {c.get('functions')} fns, {c.get('strings')} strings, "
              f"{c.get('constants')} constants, {c.get('carved')} carved")

    feats = res.get("features", {})
    if "kesakode" in feats:
        k = feats["kesakode"]
        top = sorted(k.get("verdict", {}).items(), key=lambda kv: kv[1], reverse=True)[:8]
        print(f"\nkesakode    : mode={k.get('mode')} online_used={k.get('used_online')}")
        print(f"  verdict   : {top if top else '<empty>'}")
        print(f"  counts    : {k.get('counts')}")
        if k.get("quota_left") is not None:
            print(f"  quota     : {k.get('quota_left')}/{k.get('quota_total')}")
        if k.get("skipped"):
            print(f"  skipped   : {k['skipped']}")
        if k.get("error"):
            print(f"  error     : {k['error']}")

    if "capa" in feats:
        print(f"\ncapa        : {len(feats['capa'])} capabilities")
        for m in feats["capa"][:30]:
            extra = ""
            if m.get("attack"):
                extra += f"  ATT&CK={[_term(t) for t in m['attack']]}"
            if m.get("mbc"):
                extra += f"  MBC={[_term(t) for t in m['mbc']]}"
            print(f"  - [{m.get('namespace')}] {m.get('name')}{extra}")

    if "anomalies" in feats:
        print(f"\nanomalies   : {len(feats['anomalies'])}")
        for a in feats["anomalies"][:20]:
            print(f"  - {a.get('label')} [{a.get('category')}]")
            for loc in a.get("locations", [])[:5]:
                fn = f" {loc.get('function')}+{loc.get('function_offset')}" if loc.get("function") else ""
                print(f"      -> {loc.get('address')}{fn} ({loc.get('size')} bytes)")

    if "yara" in feats:
        print(f"\nyara        : {feats['yara'] or 'none'}")
    if "constants" in feats:
        print(f"constants   : {feats['constants'] or 'none'}")

    if res.get("errors"):
        print(f"\nper-feature errors: {res['errors']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample", nargs="?", help="path to sample (omit with --health/--quota)")
    ap.add_argument("--url", required=True, help="bridge base URL, e.g. https://host:8090")
    ap.add_argument("--api-key", default=os.environ.get("MALCAT_BRIDGE_API_KEY"),
                    help="bridge API key (or env MALCAT_BRIDGE_API_KEY)")
    ap.add_argument("--features", default="kesakode",
                    help="comma list: kesakode,capa,anomalies,yara,constants,info")
    ap.add_argument("--kesakode-mode", default="online", choices=["online", "offline", "auto"])
    ap.add_argument("--filetype-force", default=None)
    ap.add_argument("--quota-reserve", type=int, default=0,
                    help="stop online kesakode when bridge quota <= this (0 = no floor)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed)")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--health", action="store_true", help="just call /health and exit")
    ap.add_argument("--quota", action="store_true", help="just call /v1/quota and exit")
    ap.add_argument("--json", action="store_true", help="print raw JSON")
    args = ap.parse_args()

    if args.insecure and urllib3 is not None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.health:
        print(json.dumps(health(args.url, args.insecure), indent=2))
        return
    if args.quota:
        if not args.api_key:
            sys.exit("--api-key required for quota")
        print(json.dumps(quota(args.url, args.api_key, args.insecure), indent=2))
        return

    if not args.sample:
        sys.exit("sample path required (or use --health/--quota)")
    if not args.api_key:
        sys.exit("--api-key required (or set MALCAT_BRIDGE_API_KEY)")
    if not os.path.isfile(args.sample):
        sys.exit(f"file not found: {args.sample}")

    features = [f.strip().lower() for f in args.features.split(",") if f.strip()]
    res = analyze(args.url, args.api_key, args.sample, features,
                  args.kesakode_mode, args.filetype_force, args.quota_reserve,
                  args.insecure, args.timeout)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        _print_report(res)


if __name__ == "__main__":
    main()
