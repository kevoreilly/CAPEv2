# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ast
import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from paramiko.client import SSHClient

from lib.cuckoo.common.sshclient import TIMEOUT, SSHJumpClient


def test_ssh_jump_client_connect_matches_paramiko_signature():
    """Paramiko 5.x removed gss_* parameters from SSHClient.connect."""
    captured = {}
    real_sig = inspect.signature(SSHClient.connect)

    def fake_connect(self, hostname, **kwargs):
        real_sig.bind(self, hostname, **kwargs)
        captured["hostname"] = hostname
        captured["kwargs"] = kwargs
        return "connected"

    client = SSHJumpClient()
    with patch.object(SSHClient, "connect", fake_connect):
        result = client.connect("example.invalid", username="cape", banner_timeout=60)

    assert result == "connected"
    assert captured["hostname"] == "example.invalid"
    assert captured["kwargs"]["username"] == "cape"
    assert captured["kwargs"]["timeout"] == TIMEOUT
    assert captured["kwargs"]["banner_timeout"] == 60
    assert not any(key.startswith("gss_") for key in captured["kwargs"])


def test_ssh_jump_client_connect_opens_jump_channel_and_rejects_both_sock():
    jump_transport = MagicMock()
    jump_transport.getpeername.return_value = ("127.0.0.1", 22)
    channel = MagicMock(name="channel")
    jump_transport.open_channel.return_value = channel

    jump_session = MagicMock()
    jump_session._transport = jump_transport

    client = SSHJumpClient(jump_session=jump_session)

    with pytest.raises(ValueError, match="mutually exclusive"):
        client.connect("target.invalid", sock=MagicMock())

    captured = {}

    def fake_connect(self, hostname, **kwargs):
        captured["kwargs"] = kwargs

    with patch.object(SSHClient, "connect", fake_connect):
        client.connect("target.invalid", port=2222)

    jump_transport.open_channel.assert_called_once_with(
        kind="direct-tcpip",
        dest_addr=("target.invalid", 2222),
        src_addr=("127.0.0.1", 22),
    )
    assert captured["kwargs"]["sock"] is channel


def test_ssh_jump_client_auth_delegates_paramiko5_signature_and_custom_handler():
    captured = {}

    def fake_auth(self, username, password, pkey, key_filenames, allow_agent, look_for_keys, passphrase):
        captured["args"] = (username, password, pkey, key_filenames, allow_agent, look_for_keys, passphrase)
        return "super-auth"

    client = SSHJumpClient()
    with patch.object(SSHClient, "_auth", fake_auth):
        result = client._auth("cape", "pw", None, [], True, False, None)

    assert result == "super-auth"
    assert captured["args"] == ("cape", "pw", None, [], True, False, None)

    handler = MagicMock()
    interactive_client = SSHJumpClient(auth_handler=handler)
    interactive_client._transport = MagicMock()
    interactive_client._auth("cape", None, None, [], False, False, None)
    interactive_client._transport.auth_interactive.assert_called_once_with(
        username="cape",
        handler=handler,
    )


def test_admin_jumpbox_connect_does_not_disable_rsa_sha2_algorithms():
    """Paramiko 5.x removed ssh-rsa (SHA-1); disabling rsa-sha2-* leaves zero RSA pubkey algorithms."""
    admin_src = (Path(__file__).resolve().parents[1] / "admin" / "admin.py").read_text(encoding="utf-8")
    tree = ast.parse(admin_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "connect":
            for kw in node.keywords:
                if kw.arg == "disabled_algorithms":
                    rendered = ast.unparse(kw.value)
                    assert "rsa-sha2-512" not in rendered and "rsa-sha2-256" not in rendered, (
                        f"admin/admin.py disables RSA-SHA2 pubkeys incompatible with Paramiko 5.x: {rendered}"
                    )
