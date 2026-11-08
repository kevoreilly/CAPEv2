# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
from unittest.mock import MagicMock

import pytest

from lib.cuckoo.common.integrations.malcat import malcat_bridge
from lib.cuckoo.common.integrations.malcat.capa import malcat_details
from lib.cuckoo.common.integrations.malcat.client import MalcatBridgeError, MalcatClient
from lib.cuckoo.common.integrations.malcat.convert import (
    capa_to_flare_shape,
    kesakode_to_similarity_rows,
    normalize_anomalies,
)
from lib.cuckoo.common.integrations.similarity.kesakode_engine import KesakodeEngine


def test_capa_to_flare_shape():
    matches = [
        {
            "name": "encrypt data using RC4",
            "namespace": "data-manipulation/encryption/rc4",
            "attack": [{"tactic": "Defense Evasion", "technique": "Obfuscated Files or Information", "id": "T1027"}],
            "mbc": [{"objective": "Cryptography", "behavior": "Encrypt Data", "method": "RC4", "id": "C0027.009"}],
        }
    ]
    out = capa_to_flare_shape(matches)
    assert out["CAPABILITY"]["data-manipulation/encryption/rc4"] == ["encrypt data using RC4"]
    assert "DEFENSE EVASION" in out["ATTCK"]
    assert "CRYPTOGRAPHY" in out["MBC"]


def test_kesakode_to_similarity_rows():
    kk = {
        "verdict": {"AgentTesla": 91.2, "CleanLib": 40.0},
        "counts": {"malware": 5, "library": 2, "clean": 1, "unknown": 0},
    }
    rows = kesakode_to_similarity_rows(kk, minimum_similarity=50.0, max_results=3)
    assert len(rows) == 1
    assert rows[0]["family"] == "AgentTesla"
    assert rows[0]["similarity"] == 91.2
    assert rows[0]["engine"] == "malcat kesakode"


def test_normalize_anomalies():
    raw = [
        {
            "label": "entrypoint outside section",
            "category": "header",
            "locations": [{"address": "0x1000", "size": 4, "function": "start", "function_offset": "0x4"}],
        },
        {"label": "", "category": "empty"},
    ]
    out = normalize_anomalies(raw)
    assert len(out) == 2
    assert out[0]["label"] == "entrypoint outside section"
    assert out[0]["locations"][0]["address"] == "0x1000"
    assert out[1]["label"] == "Unknown"


def test_analysis_cache_unlinks_temp_files_on_eviction_and_clear():
    fd1, tmp1 = tempfile.mkstemp(prefix="test_malcat_1_")
    os.close(fd1)
    fd2, tmp2 = tempfile.mkstemp(prefix="test_malcat_2_")
    os.close(fd2)

    cache = malcat_bridge.AnalysisCache(max_entries=1, ttl=600)
    e1 = cache.new_entry("sha1", MagicMock(), passes={"kesakode"})
    e1["tmp"] = tmp1
    assert os.path.exists(tmp1)

    # Adding second entry evicts sha1 and must unlink tmp1
    e2 = cache.new_entry("sha2", MagicMock(), passes={"kesakode"})
    e2["tmp"] = tmp2
    assert not os.path.exists(tmp1)
    assert os.path.exists(tmp2)

    # Clearing cache unlinks remaining tmp2
    cache.clear()
    assert not os.path.exists(tmp2)


def test_bridge_reanalyses_when_cached_entry_lacks_requested_pass(monkeypatch):
    data = b"MZ" + b"\x00" * 64

    cache = malcat_bridge.AnalysisCache(max_entries=4, ttl=600)
    monkeypatch.setattr(malcat_bridge, "_CACHE", cache)
    monkeypatch.setattr(malcat_bridge, "_BACKEND", None)

    calls = []

    def fake_malcat_analyse(data_bytes, features, filetype_force):
        calls.append(set(features))
        fd, tmp = tempfile.mkstemp(prefix="test_malcat_re_")
        os.close(fd)
        analysis = MagicMock()
        analysis.file.type = "PE"
        analysis.file.size = len(data_bytes)
        analysis.architecture = "X86"
        if "anomalies" in features:
            anom = MagicMock()
            anom.label = "suspicious section"
            anom.category = "section"
            anom.locations = [(0x1000, 4)]
            analysis.anomalies = [anom]
        else:
            analysis.anomalies = []
        return analysis, tmp

    monkeypatch.setattr(malcat_bridge, "_malcat_analyse", fake_malcat_analyse)
    monkeypatch.setattr(
        malcat_bridge,
        "_extract_kesakode",
        lambda analysis, mode, license, quota_reserve=0: {
            "mode": mode,
            "used_online": True,
            "verdict": {"TestFam": 88.0},
            "counts": {"malware": 3, "library": 0, "clean": 0, "unknown": 1},
        },
    )

    try:
        # 1. Lean Kesakode pass
        r1 = malcat_bridge.run_analysis(data, ["kesakode"], None, "online", "LIC")
        assert r1["cached"] is False
        assert r1["features"]["kesakode"]["verdict"] == {"TestFam": 88.0}
        assert len(calls) == 1

        # 2. Request anomalies on same sha256 -> must upgrade passes and re-run _malcat_analyse,
        # while preserving cached online kesakode verdict.
        r2 = malcat_bridge.run_analysis(data, ["anomalies", "kesakode"], None, "online", "LIC")
        assert r2["cached"] is False
        assert len(calls) == 2
        assert "anomalies" in calls[1]
        assert len(r2["features"]["anomalies"]) == 1
        assert r2["features"]["anomalies"][0]["label"] == "suspicious section"
        assert r2["features"]["kesakode"]["verdict"] == {"TestFam": 88.0}

        # 3. Repeat anomalies request -> now served from cache
        r3 = malcat_bridge.run_analysis(data, ["anomalies"], None, "online", "LIC")
        assert r3["cached"] is True
        assert len(calls) == 2
    finally:
        cache.clear()


def test_malcat_details_respects_category_and_enabled(monkeypatch, tmp_path):
    from lib.cuckoo.common.config import Config
    from lib.cuckoo.common.integrations.malcat import capa as malcat_capa_mod

    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 64)

    fake_client = MagicMock()
    fake_client.analyze.return_value = {
        "features": {
            "anomalies": [
                {"label": "suspicious section", "category": "section", "locations": [{"address": "0x1000", "size": 4}]}
            ]
        }
    }
    monkeypatch.setattr(malcat_capa_mod, "_get_client", lambda: fake_client)

    integ = Config("integrations")
    monkeypatch.setitem(integ.malcat, "enabled", True)
    monkeypatch.setitem(integ.malcat, "anomalies", True)
    monkeypatch.setitem(integ.malcat, "malcat_payloads", True)
    monkeypatch.setitem(integ.malcat, "malcat_dropped", False)

    assert malcat_details(str(pe_file), category="dropped", file_type="PE32 executable") == {}
    res = malcat_details(str(pe_file), category="CAPE", file_type="PE32 executable")
    assert res == {
        "anomalies": [
            {"label": "suspicious section", "category": "section", "locations": [{"address": "0x1000", "size": 4}]}
        ]
    }


def test_kesakode_engine_on_demand_skips_online(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    engine = KesakodeEngine(
        {
            "kesakode_host": "http://127.0.0.1:8090",
            "kesakode_mode": "online",
            "kesakode_on_demand": "yes",
        }
    )
    engine._available = True
    engine._client = MagicMock()
    res = engine.analyze(str(sample), "abc", "sample.exe", "payload")
    assert res.status == "on_demand"
    engine._client.analyze.assert_not_called()


def test_malcat_client_rejects_unknown_features():
    client = MalcatClient("http://127.0.0.1:8090")
    with pytest.raises(MalcatBridgeError):
        client.analyze(b"MZ", features=["nonexistent_feature"])


def test_per_engine_similarity_sources():
    from lib.cuckoo.common.integrations.similarity.mcrit_engine import McritEngine

    opts = {
        "similarity_payloads": "yes",
        "similarity_procdump": "yes",
        "similarity_dropped": "no",
        "similarity_submittedfile": "no",
        "kesakode_procdump": "no",
        "mcrit_dropped": "yes",
    }
    kk = KesakodeEngine(opts)
    mc = McritEngine(opts)

    assert kk.accepts_source("payload") is True
    assert kk.accepts_source("procdump") is False
    assert kk.accepts_source("dropped") is False

    assert mc.accepts_source("payload") is True
    assert mc.accepts_source("procdump") is True
    assert mc.accepts_source("dropped") is True


def test_capa_routes_to_malcat_and_respects_category_options(monkeypatch):
    from lib.cuckoo.common.integrations import capa as capa_mod

    monkeypatch.setattr(capa_mod, "HAVE_FLARE_CAPA", True)
    monkeypatch.setattr(capa_mod, "HAVE_MALCAT_CAPA", True)
    monkeypatch.setattr(
        capa_mod,
        "malcat_capa_details",
        lambda file_path, category=False, on_demand=False, results=None: {"CAPABILITY": {"ns": [category]}},
        raising=False,
    )
    monkeypatch.setattr(capa_mod.integrations_conf.flare_capa, "enabled", True)
    monkeypatch.setattr(capa_mod.integrations_conf.flare_capa, "on_demand", False)
    monkeypatch.setitem(capa_mod.integrations_conf.flare_capa, "cape", True)
    monkeypatch.setitem(capa_mod.integrations_conf.flare_capa, "procdump", False)

    assert capa_mod.flare_capa_details("/tmp/fake.exe", "cape") == {"CAPABILITY": {"ns": ["cape"]}}
    assert capa_mod.flare_capa_details("/tmp/fake.exe", "procdump") == {}
    assert capa_mod.flare_capa_details("/tmp/fake.exe", "procdump", on_demand=True) == {"CAPABILITY": {"ns": ["procdump"]}}


def test_run_processing_resolves_similarity_from_integrations_conf(monkeypatch):
    from lib.cuckoo.core import plugins as plugins_mod
    from modules.processing.similarity import Similarity

    assert "similarity" not in plugins_mod.processing_cfg.fullconfig
    assert "similarity" in plugins_mod.integrations_cfg.fullconfig

    results = {"statistics": {"processing": []}}
    rp = plugins_mod.RunProcessing({"id": 1, "platform": "windows"}, results)

    # Disabled by default in integrations.conf
    monkeypatch.setattr(plugins_mod.integrations_cfg.similarity, "enabled", False)
    assert rp.process(Similarity) is None

    # Enabled in integrations.conf -> executes Similarity.run()
    monkeypatch.setattr(plugins_mod.integrations_cfg.similarity, "enabled", True)
    monkeypatch.setattr(Similarity, "run", lambda self: {"enabled_engines": ["kesakode"]})
    assert rp.process(Similarity) == {"similarity": {"enabled_engines": ["kesakode"]}}


def test_kesakode_to_similarity_rows_applies_engine_options():
    kk = {
        "verdict": {"MSVC_Runtime": 95.0, "AgentTesla": 42.0},
    }
    rows = kesakode_to_similarity_rows(
        kk,
        options={
            "minimum_similarity": "50",
            "max_results": "3",
            "exclude_families": "msvc",
            "best_match": "yes",
        },
    )
    assert len(rows) == 1
    assert rows[0]["family"] == "AgentTesla"
    assert rows[0]["similarity"] == 42.0
    assert rows[0]["low_confidence"] is True
    assert rows[0]["engine"] == "malcat kesakode"


def test_malcat_details_prefetches_capa_in_single_bridge_call(monkeypatch, tmp_path):
    from lib.cuckoo.common.config import Config
    from lib.cuckoo.common.integrations.malcat import capa as malcat_capa_mod

    malcat_capa_mod._CAPA_PREFETCH_CACHE.clear()
    pe_file = tmp_path / "payload.exe"
    pe_file.write_bytes(b"MZ" + b"\x90" * 64)

    fake_client = MagicMock()
    fake_client.analyze.return_value = {
        "features": {
            "anomalies": [
                {"label": "suspicious section", "category": "section", "locations": [{"address": "0x1000", "size": 4}]}
            ],
            "capa": [
                {
                    "name": "encrypt data using RC4",
                    "namespace": "data-manipulation/encryption/rc4",
                    "attack": [],
                    "mbc": [],
                }
            ],
        }
    }
    monkeypatch.setattr(malcat_capa_mod, "_get_client", lambda: fake_client)

    integ = Config("integrations")
    monkeypatch.setitem(integ.malcat, "enabled", True)
    monkeypatch.setitem(integ.malcat, "anomalies", True)
    monkeypatch.setitem(integ.malcat, "malcat_payloads", True)
    monkeypatch.setitem(integ.flare_capa, "enabled", True)
    monkeypatch.setitem(integ.flare_capa, "malcat_capa", True)
    monkeypatch.setitem(integ.flare_capa, "on_demand", False)
    monkeypatch.setitem(integ.flare_capa, "cape", True)

    anom = malcat_details(str(pe_file), category="CAPE", file_type="PE32 executable")
    assert len(anom["anomalies"]) == 1
    assert fake_client.analyze.call_count == 1
    assert set(fake_client.analyze.call_args.kwargs["features"]) == {"anomalies", "capa"}

    # Subsequent malcat_capa_details call reuses prefetched capa without a 2nd HTTP call
    capa_res = malcat_capa_mod.malcat_capa_details(str(pe_file), category="cape")
    assert capa_res["CAPABILITY"]["data-manipulation/encryption/rc4"] == ["encrypt data using RC4"]
    assert fake_client.analyze.call_count == 1


def test_static_file_info_runs_malcat_before_flare_capa(monkeypatch, tmp_path):
    import lib.cuckoo.common.integrations.file_extra_info as fei_mod

    pe_file = tmp_path / "sample.exe"
    pe_file.write_bytes(b"MZ" + b"\x90" * 64)
    call_order = []

    def fake_malcat_details(file_path, category="static", file_type=""):
        call_order.append("malcat")
        return {"anomalies": [{"label": "test"}]}

    def fake_flare_capa_details(file_path, category="static", **kwargs):
        call_order.append("flare_capa")
        return {"CAPABILITY": {"ns": ["cap"]}}

    class _FakePE:
        def __init__(self, path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def run(self, task_id):
            return {}

    monkeypatch.setattr(fei_mod, "HAVE_MALCAT", True)
    monkeypatch.setattr(fei_mod, "HAVE_PEFILE", True)
    monkeypatch.setattr(fei_mod, "HAVE_FLARE_CAPA", True)
    monkeypatch.setattr(fei_mod, "HAVE_FLOSS", False)
    monkeypatch.setattr(fei_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(fei_mod, "malcat_details", fake_malcat_details, raising=False)
    monkeypatch.setattr(fei_mod, "flare_capa_details", fake_flare_capa_details, raising=False)
    monkeypatch.setattr(fei_mod, "PortableExecutable", _FakePE, raising=False)
    monkeypatch.setattr(fei_mod, "generic_file_extractors", lambda *a, **k: None)

    data_dict = {"type": "PE32 executable (GUI) Intel 80386, for MS Windows", "sha256": "a" * 64}
    fei_mod.static_file_info(
        data_dict,
        str(pe_file),
        "1",
        "exe",
        "",
        str(tmp_path),
        {},
        {"sha256": set()},
        category="static",
    )
    assert call_order == ["malcat", "flare_capa"]




