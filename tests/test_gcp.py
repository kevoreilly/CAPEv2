# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from lib.cuckoo.common import gcp


def test_gcp_autodiscovery_posts_json_with_auth_token_and_sleeps_once_when_empty(monkeypatch):
    class _StopLoop(Exception):
        pass

    client = gcp.GCP()

    # 1. Empty instance list sleeps once per iteration (does not double-sleep).
    sleeps = []

    def _sleep_empty(sec):
        sleeps.append(sec)
        raise _StopLoop

    with (
        patch.object(client, "list_instances", return_value={}),
        patch.object(gcp.time, "sleep", side_effect=_sleep_empty),
    ):
        with pytest.raises(_StopLoop):
            client.autodiscovery()
    assert len(sleeps) == 1

    # 2. Discovered healthy worker is registered via JSON body with X-API-Token and timeout.
    fake_dist_cfg = SimpleNamespace(distributed={"auth_token": "secret-token"})
    fake_resp = MagicMock(ok=True, status_code=200)
    monkeypatch.setattr(
        gcp,
        "gcp_cfg",
        SimpleNamespace(
            gcp={"project": "example-project", "zone": "us-central1-a"},
            distributed={"autodiscovery_interval": 30, "apikey": "worker-key"},
        ),
    )

    with (
        patch.object(gcp, "Config", return_value=fake_dist_cfg),
        patch.object(client, "list_instances", return_value={"worker-1": ["10.0.0.5"]}),
        patch.object(gcp, "check_node_up", return_value=True),
        patch.object(gcp.requests, "post", return_value=fake_resp) as mock_post,
        patch.object(gcp.time, "sleep", side_effect=_StopLoop),
    ):
        with pytest.raises(_StopLoop):
            client.autodiscovery()

    mock_post.assert_called_once_with(
        "http://localhost:9003/node",
        json={
            "name": "worker-1",
            "url": "http://10.0.0.5:8000/apiv2/",
            "enabled": True,
            "apikey": "worker-key",
        },
        headers={"X-API-Token": "secret-token"},
        timeout=30,
    )


def test_gcp_list_instances_token_mode_falls_back_to_internal_ip(monkeypatch):
    client = gcp.GCP()
    client.project_id = "example-project"
    client.zones = ["us-central1-a"]
    client.token = "tok"
    client.headers = {"Authorization": "Bearer tok"}

    fake_resp = MagicMock()
    fake_resp.json.return_value = {
        "items": [
            {
                "name": "cape-server-1",
                "networkInterfaces": [{"networkIP": "10.0.0.9"}],
            },
            {
                "name": "unrelated-vm",
                "networkInterfaces": [{"networkIP": "10.0.0.10"}],
            },
        ]
    }

    with patch.object(gcp.requests, "get", return_value=fake_resp):
        result = client.list_instances()

    assert result == {"cape-server-1": ["10.0.0.9"]}
