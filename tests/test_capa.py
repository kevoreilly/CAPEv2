# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import importlib
import sys
from types import ModuleType, SimpleNamespace

import pytest

import lib.cuckoo.common.integrations.capa as capa_mod
import lib.cuckoo.common.path_utils as path_utils_mod
from lib.cuckoo.common.config import ConfigMeta


def _install_fake_capa_tree(monkeypatch, ver_str: str):
    module_names = [
        "capa",
        "capa.version",
        "capa.capabilities",
        "capa.capabilities.common",
        "capa.engine",
        "capa.features",
        "capa.features.common",
        "capa.features.freeze",
        "capa.features.freeze.features",
        "capa.loader",
        "capa.main",
        "capa.render",
        "capa.render.default",
        "capa.render.json",
        "capa.render.result_document",
        "capa.render.utils",
        "capa.rules",
        "capa.exceptions",
        "pydantic_core",
        "pydantic_core._pydantic_core",
    ]
    for name in module_names:
        mod = ModuleType(name)
        monkeypatch.setitem(sys.modules, name, mod)

    sys.modules["capa.version"].__version__ = ver_str
    sys.modules["capa.exceptions"].EmptyReportError = type("EmptyReportError", (Exception,), {})
    sys.modules["capa.exceptions"].UnsupportedFormatError = type("UnsupportedFormatError", (Exception,), {})
    sys.modules["capa.features.common"].FORMAT_AUTO = "auto"
    sys.modules["capa.features.common"].OS_AUTO = "auto"
    sys.modules["capa.rules"].InvalidRule = type("InvalidRule", (Exception,), {})
    sys.modules["capa.rules"].InvalidRuleSet = type("InvalidRuleSet", (Exception,), {})
    sys.modules["capa.rules"].InvalidRuleWithPath = type("InvalidRuleWithPath", (Exception,), {})
    sys.modules["pydantic_core._pydantic_core"].ValidationError = type("ValidationError", (Exception,), {})


@pytest.mark.parametrize(
    ("capa_ver", "expected_compatible"),
    [
        ("9.3.1", True),
        ("10.0.0", True),
        ("8.0.0", False),
        ("11.0.0", False),
    ],
)
def test_capa_version_compatibility_gate(monkeypatch, custom_conf_path, capsys, capa_ver, expected_compatible):
    conf_file = custom_conf_path / "integrations.conf"
    conf_file.write_text("[flare_capa]\nenabled = yes\nmalcat_capa = no\non_demand = no\n", encoding="utf-8")
    ConfigMeta.refresh()

    _install_fake_capa_tree(monkeypatch, capa_ver)
    monkeypatch.setattr(path_utils_mod, "path_exists", lambda _: False)

    try:
        importlib.reload(capa_mod)
        captured = capsys.readouterr().out
        assert ("FLARE-CAPA missed or incompatible version" not in captured) is expected_compatible
        if expected_compatible:
            assert capa_mod.capa_compatible_versions == {"9", "10"}
    finally:
        if conf_file.exists():
            conf_file.unlink()
        ConfigMeta.refresh()
        monkeypatch.undo()
        importlib.reload(capa_mod)


# capa.loader.collect_metadata() signatures of the supported capa majors.
# capa 10.0.0 removed the os_ parameter (mandiant/capa#3076).
def _collect_metadata_capa9(argv, input_path, input_format, os_, rules_path, extractor, capabilities):
    return SimpleNamespace(analysis=SimpleNamespace(), os_=os_)


def _collect_metadata_capa10(argv, input_path, input_format, rules_path, extractor, capabilities):
    return SimpleNamespace(analysis=SimpleNamespace(), os_=None)


def _install_fake_loaded_capa(monkeypatch, collect_metadata):
    """Make capa_mod look as if capa and its rules were loaded, with a stubbed analysis pipeline."""
    extractor = object()
    fake_capa = SimpleNamespace(
        features=SimpleNamespace(
            common=SimpleNamespace(),
            extractors=SimpleNamespace(
                cape=SimpleNamespace(
                    extractor=SimpleNamespace(CapeExtractor=SimpleNamespace(from_report=lambda results: extractor))
                )
            ),
        ),
        loader=SimpleNamespace(
            BACKEND_VIV="vivisect",
            get_extractor=lambda *args, **kwargs: extractor,
            collect_metadata=collect_metadata,
            compute_layout=lambda rules, extractor, matches: "layout",
        ),
        capabilities=SimpleNamespace(
            common=SimpleNamespace(find_capabilities=lambda rules, extractor, disable_progress=True: SimpleNamespace(matches={}))
        ),
    )
    fake_rd = SimpleNamespace(
        ResultDocument=SimpleNamespace(from_capa=lambda meta, rules, matches: {"os": meta.os_, "layout": meta.analysis.layout})
    )

    monkeypatch.setattr(capa_mod, "_ensure_capa_loaded", lambda force=False: True)
    monkeypatch.setattr(capa_mod, "render_dictionary", lambda doc: doc)
    monkeypatch.setattr(capa_mod, "rules", object())
    monkeypatch.setattr(capa_mod, "signatures", [])
    monkeypatch.setattr(capa_mod, "capa", fake_capa, raising=False)
    monkeypatch.setattr(capa_mod, "rd", fake_rd, raising=False)
    monkeypatch.setattr(capa_mod, "FORMAT_AUTO", "auto", raising=False)
    monkeypatch.setattr(capa_mod, "OS_AUTO", "auto", raising=False)
    for name in ("EmptyReportError", "UnsupportedFormatError", "ValidationError"):
        monkeypatch.setattr(capa_mod, name, type(name, (Exception,), {}), raising=False)
    monkeypatch.setitem(sys.modules, "capa.helpers", ModuleType("capa.helpers"))


@pytest.mark.parametrize(
    ("collect_metadata", "expected_os"),
    [(_collect_metadata_capa9, "auto"), (_collect_metadata_capa10, None)],
    ids=["capa9", "capa10"],
)
@pytest.mark.parametrize(
    "run_capa",
    [
        lambda path: capa_mod._run_capa_static(path, skip_packed=False),
        lambda path: capa_mod._run_capa_report(path, {"behavior": {}}),
    ],
    ids=["static", "report"],
)
def test_capa_collect_metadata_signature_compatibility(monkeypatch, tmp_path, collect_metadata, expected_os, run_capa):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    _install_fake_loaded_capa(monkeypatch, collect_metadata)

    assert run_capa(str(sample)) == {"os": expected_os, "layout": "layout"}


def test_capa_loader_imports_cape_extractor(monkeypatch):
    # capa 9 imported the CAPE report extractor at the top of capa.loader; capa 10 imports it lazily.
    # _run_capa_report() needs it, so loading capa must import it explicitly.
    pytest.importorskip("capa.features.extractors.cape.extractor")
    import capa.features.extractors

    for name in [m for m in sys.modules if m.startswith("capa.features.extractors.cape")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.delattr(capa.features.extractors, "cape", raising=False)
    monkeypatch.setattr(capa_mod, "path_exists", lambda _: False)
    monkeypatch.setattr(capa_mod, "_CAPA_MODULES_LOADED", False)

    capa_mod._ensure_capa_loaded(force=True)

    assert hasattr(capa.features.extractors, "cape")
