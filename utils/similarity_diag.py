#!/usr/bin/env python3
# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Diagnostic for the code-similarity integration.

Run from the CAPE root inside CAPE's venv:

    python3 utils/similarity_diag.py
    python3 utils/similarity_diag.py /path/to/a/payload.bin

No argument: checks config + engine availability.
With a file: detects its format, checks which engines accept it, submits
it, and prints the matches — confirming the full path end-to-end.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.getcwd())


def main():
    print("=" * 60)
    print("CAPE code-similarity diagnostic")
    print("=" * 60)

    try:
        from lib.cuckoo.common.config import Config
        options = dict(Config("integrations").get("similarity") or {})
    except Exception as err:
        print(f"[FAIL] Could not read [similarity] from integrations.conf: {err}")
        return
    if not options:
        print("[FAIL] [similarity] section empty or missing.")
        return
    print("[ OK ] [similarity] config read. Effective values:")
    for key in sorted(options):
        print(f"         {key} = {options[key]!r}")

    try:
        proc = dict(Config("processing").get("similarity") or {})
        enabled = str(proc.get("enabled")).lower() in ("1", "true", "yes", "on")
        print(f"[{'OK' if enabled else 'WARN'}] processing.conf [similarity] enabled = {proc.get('enabled')}")
    except Exception as err:
        print(f"[WARN] processing.conf has no [similarity] section: {err}")

    from lib.cuckoo.common.integrations.similarity.registry import get_enabled_engines
    engines = get_enabled_engines(options)
    if not engines:
        print("[FAIL] No engines available. Either none enabled, or the server")
        print(f"       did not answer GET {options.get('mcrit_host')}/version .")
        print("       Test:  curl <mcrit_host>/version")
        return
    for e in engines:
        print(f"[ OK ] Engine '{e.name}' available. Supported formats: {sorted(e.supported_formats)}")

    if len(sys.argv) <= 1:
        print("\nPass a file path to submit it and see matches:")
        print("    python3 utils/similarity_diag.py /path/to/payload.bin")
        return

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"[FAIL] File not found: {path}")
        return

    from lib.cuckoo.common.integrations.similarity.base import detect_format
    with open(path, "rb") as fh:
        data = fh.read()
    sha256 = hashlib.sha256(data).hexdigest()
    fmt = detect_format(None, magic=data[:8])
    print(f"\nSubmitting {path}")
    print(f"  size={len(data)} sha256={sha256[:16]} detected_format={fmt}")

    for engine in engines:
        print(f"\n--- engine: {engine.name} ---")
        if not engine.accepts_format(fmt):
            print(f"  SKIP: {engine.name} does not support format '{fmt}' "
                  f"(supports {sorted(engine.supported_formats)})")
            continue
        result = engine.analyze(file_path=path, sha256=sha256,
                                filename=os.path.basename(path), source="manual")
        print(f"  status: {result.status}" + (f"  error: {result.error}" if result.error else ""))
        for m in result.matches:
            print(f"  MATCH  family={m.family or '(none)':20} "
                  f"sim={m.similarity:5.1f}%  sha256={(m.sample_sha256 or '')[:16]}")
        if not result.matches and result.status == "no_match":
            print("  (no matches — empty corpus, below threshold, or genuinely dissimilar)")

    print("\nDone.")


if __name__ == "__main__":
    main()
