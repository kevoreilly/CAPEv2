import json

import pytest
from pytest_mock import MockerFixture

from lib.cuckoo.common import hypervisor_config
from lib.cuckoo.common.dictionary import Dictionary


def make_conf(**overrides):
    proxmox = Dictionary(
        hostname="proxmox.example:8006",
        username="cape@pve",
        password="secret",
        nodes="node-a",
        action="reset",
    )
    proxmox.update(overrides)
    return Dictionary(proxmox=proxmox, Node_1=Dictionary(win10_1=126))


@pytest.fixture
def post(mocker: MockerFixture):
    ticket = mocker.Mock(text=json.dumps({"data": {"ticket": "TICKET", "CSRFPreventionToken": "CSRF"}}))
    action = mocker.Mock(status_code=200)
    return mocker.patch.object(hypervisor_config.requests, "post", side_effect=[ticket, action])


RESET_URL = "https://proxmox.example:8006/api2/json/nodes/node-a/qemu/126/status/reset"


def test_shutdown_with_password_uses_ticket(monkeypatch, post):
    monkeypatch.setattr(hypervisor_config, "proxmox_conf", make_conf())

    hypervisor_config.proxmox_shutdown_vm("win10_1")

    assert post.call_count == 2
    ticket_call, action_call = post.call_args_list
    assert ticket_call.args == ("https://proxmox.example:8006/api2/json/access/ticket",)
    assert ticket_call.kwargs == {"data": {"username": "cape@pve", "password": "secret"}, "verify": False}
    assert action_call.args == (RESET_URL,)
    assert action_call.kwargs == {
        "headers": {"cookie": "PVEAuthCookie=TICKET", "CSRFPreventionToken": "CSRF"},
        "verify": False,
    }


def test_shutdown_with_api_token_skips_ticket(monkeypatch, mocker: MockerFixture, post):
    conf = make_conf(password=None, token_name="cape", token_value="token-secret")
    monkeypatch.setattr(hypervisor_config, "proxmox_conf", conf)
    post.side_effect = [mocker.Mock(status_code=200)]

    hypervisor_config.proxmox_shutdown_vm("win10_1")

    post.assert_called_once_with(
        RESET_URL,
        headers={"Authorization": "PVEAPIToken=cape@pve!cape=token-secret"},
        verify=False,
    )


@pytest.mark.parametrize(
    ("ignore_ssl", "verify"),
    [(None, False), (True, False), (False, True), (1, False), (0, True)],
)
def test_shutdown_ignore_ssl_option(monkeypatch, post, ignore_ssl, verify):
    monkeypatch.setattr(hypervisor_config, "proxmox_conf", make_conf(ignore_ssl=ignore_ssl))

    hypervisor_config.proxmox_shutdown_vm("win10_1")

    assert [call.kwargs["verify"] for call in post.call_args_list] == [verify, verify]


def test_shutdown_reports_rejected_action(monkeypatch, mocker: MockerFixture, post, capsys):
    conf = make_conf(password=None, token_name="cape", token_value="wrong")
    monkeypatch.setattr(hypervisor_config, "proxmox_conf", conf)
    post.side_effect = [mocker.Mock(status_code=401, reason="Authentication failed!")]

    hypervisor_config.proxmox_shutdown_vm("win10_1")

    output = capsys.readouterr().out
    assert "reset failed: 401 Authentication failed!" in output
    assert "successfully" not in output
