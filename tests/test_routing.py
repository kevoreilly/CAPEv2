# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
from types import SimpleNamespace

import pytest

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.routing import is_no_route, normalize_task_route, resolve_task_route
from lib.cuckoo.core.plugins import RunAuxiliary


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, None),
        (False, None),
        ("", None),
        ("   ", None),
        ("none", "none"),
        ("drop", "drop"),
        ("false", "false"),
        ("  vpn_uk  ", "vpn_uk"),
        ("internet", "internet"),
    ],
)
def test_normalize_task_route(raw, expected):
    assert normalize_task_route(raw) == expected


@pytest.mark.parametrize(
    "task_route, conf_route, expected",
    [
        (None, "none", "none"),
        (None, "vpn_uk", "vpn_uk"),
        ("", "internet", "internet"),
        (False, "inetsim", "inetsim"),
        ("none", "vpn_uk", "none"),
        ("drop", "internet", "drop"),
        ("false", "vpn_uk", "false"),
        ("  tor  ", "none", "tor"),
        (None, None, "none"),
        (None, False, "none"),
        (None, "", "none"),
    ],
)
def test_resolve_task_route(task_route, conf_route, expected):
    fake_conf = SimpleNamespace(routing=SimpleNamespace(route=conf_route))
    assert resolve_task_route(task_route, fake_conf) == expected


@pytest.mark.parametrize(
    "route, expected",
    [
        (None, True),
        (False, True),
        ("", True),
        ("   ", True),
        ("none", True),
        ("None", True),
        ("NONE", True),
        ("drop", True),
        ("DROP", True),
        ("false", True),
        ("False", True),
        ("internet", False),
        ("vpn0", False),
        ("inetsim", False),
        ("tor", False),
        ("gw1", False),
    ],
)
def test_is_no_route(route, expected):
    assert is_no_route(route) is expected


def test_run_auxiliary_passes_resolved_route_to_modules(monkeypatch):
    seen = {}

    class _DummyAux(Auxiliary):
        def start(self):
            seen["route"] = self.route
            seen["task"] = self.task
            seen["machine"] = self.machine

        def stop(self):
            pass

    monkeypatch.setattr("lib.cuckoo.core.plugins.list_plugins", lambda group=None: [_DummyAux])
    monkeypatch.setattr(
        "lib.cuckoo.core.plugins.Config",
        lambda name=None: SimpleNamespace(get=lambda _mod: SimpleNamespace(enabled=True)),
    )

    task = SimpleNamespace(id=7, route=None)
    machine = SimpleNamespace(label="win10")
    runner = RunAuxiliary(task=task, machine=machine, route="gw2")
    runner.start()

    assert seen["route"] == "gw2"
    assert seen["task"] is task
    assert seen["machine"] is machine


def test_polarproxy_and_sslproxy_use_resolved_route(monkeypatch, tmp_path):
    import modules.auxiliary.PolarProxy as polarproxy_mod
    import modules.auxiliary.SSLProxy as sslproxy_mod

    fake_routing = SimpleNamespace(
        routing=SimpleNamespace(route="inetsim", rt_table="main"),
        inetsim=SimpleNamespace(server="192.168.1.2"),
        gw2=SimpleNamespace(rt_table="202"),
    )
    fake_routing.get = lambda section: getattr(fake_routing, section)
    monkeypatch.setattr(polarproxy_mod, "routing", fake_routing)
    monkeypatch.setattr(polarproxy_mod, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(sslproxy_mod, "Config", lambda name=None: fake_routing)
    monkeypatch.setattr(sslproxy_mod, "CUCKOO_ROOT", str(tmp_path))

    # PolarProxy: task.route=None falls back to routing.conf route="inetsim".
    pp = polarproxy_mod.PolarProxyThread(SimpleNamespace(id=1, route=None), SimpleNamespace(resultserver_port=2042))
    pp.block_domains = None
    pp.bypass_domains = None
    (tmp_path / "storage" / "analyses" / "1" / "polarproxy").mkdir(parents=True)
    pp.generate_ruleset()
    ruleset1 = json.loads((tmp_path / "storage" / "analyses" / "1" / "polarproxy" / "ruleset.json").read_text())
    assert ruleset1["default"]["action"] == {"type": "terminate", "target": "192.168.1.2:80"}

    # PolarProxy: explicit runtime route="internet" overrides routing.conf "inetsim".
    pp2 = polarproxy_mod.PolarProxyThread(
        SimpleNamespace(id=2, route=None), SimpleNamespace(resultserver_port=2042), route="internet"
    )
    pp2.block_domains = None
    pp2.bypass_domains = None
    (tmp_path / "storage" / "analyses" / "2" / "polarproxy").mkdir(parents=True)
    pp2.generate_ruleset()
    ruleset2 = json.loads((tmp_path / "storage" / "analyses" / "2" / "polarproxy" / "ruleset.json").read_text())
    assert ruleset2["default"]["action"] == {"type": "inspect"}

    # SSLProxy: concrete runtime route="gw2" resolves gw2's rt_table even when task.route is None.
    sp = sslproxy_mod.SSLProxyThread(SimpleNamespace(id=3, route=None), SimpleNamespace(resultserver_port=2042), route="gw2")
    assert sp.route == "gw2"
    assert sp.rt_table == "202"

    # SSLProxy: downgraded runtime route="none" yields empty rt_table even when task.route was "gw2".
    sp_drop = sslproxy_mod.SSLProxyThread(
        SimpleNamespace(id=4, route="gw2"), SimpleNamespace(resultserver_port=2042), route="none"
    )
    assert sp_drop.route == "none"
    assert sp_drop.rt_table == ""
