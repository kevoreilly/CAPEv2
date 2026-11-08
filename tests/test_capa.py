# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import importlib
import sys
from types import ModuleType

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
