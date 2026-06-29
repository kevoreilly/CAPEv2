#!/usr/bin/env python3
# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Diagnostic for the threat-intelligence integration.

Run from the CAPE root inside CAPE's venv:

    python3 utils/threatintelligence_diag.py
    python3 utils/threatintelligence_diag.py 139.180.203.104     # indicator
    python3 utils/threatintelligence_diag.py evil-domain.com      # indicator
    python3 utils/threatintelligence_diag.py win.castle_stealer   # family (Malpedia)
    python3 utils/threatintelligence_diag.py "Cobalt Strike"      # family (resolve)

No argument: checks config + engine availability.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.getcwd())


def _looks_like_ip(value):
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def main():
    print("=" * 60)
    print("CAPE threat-intelligence diagnostic")
    print("=" * 60)

    try:
        from lib.cuckoo.common.config import Config
        options = dict(Config("integrations").get("threatintelligence") or {})
    except Exception as err:
        print(f"[FAIL] Could not read [threatintelligence] from integrations.conf: {err}")
        return
    if not options:
        print("[FAIL] [threatintelligence] section empty or missing.")
        return
    print("[ OK ] [threatintelligence] config read. Effective values:")
    for key in sorted(options):
        shown = options[key]
        if key.endswith(("_api", "_key", "_token", "_secret")) and shown:
            shown = "<set>"
        print(f"         {key} = {shown!r}")

    from lib.cuckoo.common.integrations.threatintelligence.registry import (
        get_enabled_family_providers, get_enabled_indicator_providers,
    )
    ind = get_enabled_indicator_providers(options)
    fam = get_enabled_family_providers(options)
    for p in ind:
        print(f"[ OK ] Indicator engine '{p.name}' available. Types: {sorted(p.supported_indicators)}")
    for p in fam:
        print(f"[ OK ] Family engine '{p.name}' available.")
    if not ind and not fam:
        print("[FAIL] No engines available (none enabled, or enabled-but-unavailable,")
        print("       e.g. threatfox_api / Auth-Key not set).")
        return

    if len(sys.argv) <= 1:
        print("\nPass an indicator (IP/domain) or a family (name or Malpedia id) to test it.")
        return

    from lib.cuckoo.common.integrations.threatintelligence.base import (
        IND_DOMAIN, IND_IP, looks_like_malpedia_id,
    )
    arg = sys.argv[1].strip()

    # Family if it looks like a Malpedia id or contains a space / no dotted-host shape.
    treat_as_family = looks_like_malpedia_id(arg) or (" " in arg)

    if not treat_as_family and ind:
        itype = IND_IP if _looks_like_ip(arg) else IND_DOMAIN
        print(f"\n[indicator] {arg!r} as {itype}")
        for p in ind:
            if not p.accepts_indicator(itype):
                continue
            res = p.lookup(arg, itype)
            print(f"  {p.name}: status={res.status}" + (f" error={res.error}" if res.error else ""))
            for m in res.matches:
                print(f"    TAG [{m.tag}] confidence={m.confidence_level} ioc={m.ioc} family={m.malware}")

    if fam:
        print(f"\n[family] resolving/fetching {arg!r}")
        for p in fam:
            is_id = looks_like_malpedia_id(arg)
            card = p.enrich(arg, is_id=is_id)
            if not card:
                print(f"  {p.name}: no card (unresolved or unknown family)")
                continue
            print(f"  {p.name}: {card.common_name} ({card.family_id})")
            if card.aliases:
                print(f"    aliases: {', '.join(card.aliases[:8])}")
            if card.description:
                print(f"    description: {card.description[:200]}{'...' if len(card.description) > 200 else ''}")
            for ref in card.references:
                print(f"    ref: {ref['label']}  {ref['url']}")
    print("\nDone.")


if __name__ == "__main__":
    main()
