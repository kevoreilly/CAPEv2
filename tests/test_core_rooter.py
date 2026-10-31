from types import SimpleNamespace

import pytest

from lib.cuckoo.core import rooter as core_rooter


def _routing(route="none", vpn=False, tor=False, inetsim=False, socks5=False, nexthop=None):
    cfg = SimpleNamespace(
        routing=SimpleNamespace(route=route),
        vpn=SimpleNamespace(enabled=vpn),
        tor=SimpleNamespace(enabled=tor),
        inetsim=SimpleNamespace(enabled=inetsim),
        socks5=SimpleNamespace(enabled=socks5),
    )
    if nexthop is not None:
        cfg.nexthop = SimpleNamespace(enabled=nexthop)
    return cfg


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({}, False),
        ({"nexthop": False}, False),
        ({"route": "internet"}, True),
        ({"vpn": True}, True),
        ({"tor": True}, True),
        ({"inetsim": True}, True),
        ({"socks5": True}, True),
        ({"nexthop": True}, True),
    ],
)
def test_rooter_required(kwargs, expected):
    assert core_rooter.rooter_required(_routing(**kwargs)) is expected


def test_rooter_unreachable_returns_error_dict(mocker):
    mocker.patch.object(core_rooter, "send_socket_command", return_value=None)
    resp = core_rooter.rooter("drop_enable", "192.168.122.10", "2042")
    assert resp["exception"]
    assert resp["output"] is None
    assert resp[core_rooter.ROOTER_UNAVAILABLE] is True


def test_rooter_passes_response_through(mocker):
    mocker.patch.object(core_rooter, "send_socket_command", return_value={"output": True, "exception": None})
    resp = core_rooter.rooter("nic_available", "eth0")
    assert resp == {"output": True, "exception": None}
    assert core_rooter.ROOTER_UNAVAILABLE not in resp
