import asyncio
import hashlib
import logging
from importlib import import_module
from types import SimpleNamespace

timeout_manager_module = import_module("guac.timeout_manager")


class TestSessionTimeoutManager:
    def test_idle_timeout_defaults_to_zero_when_not_configured(self, monkeypatch):
        monkeypatch.setattr(timeout_manager_module, "web_cfg", SimpleNamespace())
        manager = timeout_manager_module.SessionTimeoutManager("192.168.56.20", "tester")
        assert manager.idle_timeout_seconds == 0
        assert manager.activity_check_interval is None
        manager.last_activity = 0
        assert manager.is_timed_out() is False

    def test_idle_timeout_zero_disables_timeout_checks(self, monkeypatch):
        monkeypatch.setattr(
            timeout_manager_module,
            "web_cfg",
            SimpleNamespace(guacamole=SimpleNamespace(idle_timeout_seconds=0, activity_check_interval=1)),
        )
        manager = timeout_manager_module.SessionTimeoutManager("192.168.56.21", "tester")
        assert manager.idle_timeout_seconds == 0
        assert manager.activity_check_interval is None
        manager.last_activity = 0
        assert manager.is_timed_out() is False

    def test_complete_analysis_creates_signal_folder(self, monkeypatch):
        """Signal folder is created on the guest when task_id is available."""
        manager = timeout_manager_module.SessionTimeoutManager("192.168.56.22", "tester", task_id="321")
        expected_folder = hashlib.md5("cape-321".encode()).hexdigest()
        requested = {"mkdir": None}

        async def fake_get_json(vm_ip, path):
            if path == "/environ":
                return {"environ": {"TMP": "/tmp/cape"}}
            if path == "/system":
                return {"system": "Linux"}
            raise AssertionError(f"Unexpected path: {path}")

        async def fake_post_form(vm_ip, path, data):
            assert path == "/mkdir"
            requested["mkdir"] = data["dirpath"]
            return 200

        monkeypatch.setattr(timeout_manager_module, "_agent_get_json", fake_get_json)
        monkeypatch.setattr(timeout_manager_module, "_agent_post_form", fake_post_form)
        assert asyncio.run(manager.complete_analysis()) is True
        assert requested["mkdir"] == f"/tmp/cape/{expected_folder}"

    def test_complete_analysis_windows_path(self, monkeypatch):
        """Signal folder uses backslash on Windows guests."""
        manager = timeout_manager_module.SessionTimeoutManager("192.168.56.23", "tester", task_id="654")
        expected_folder = hashlib.md5("cape-654".encode()).hexdigest()
        requested = {"mkdir": None}

        async def fake_get_json(vm_ip, path):
            if path == "/environ":
                return {"environ": {"TMP": "C:\\Temp"}}
            if path == "/system":
                return {"system": "Windows"}
            raise AssertionError(f"Unexpected path: {path}")

        async def fake_post_form(vm_ip, path, data):
            assert path == "/mkdir"
            requested["mkdir"] = data["dirpath"]
            assert "\\" in data["dirpath"]
            return 200

        monkeypatch.setattr(timeout_manager_module, "_agent_get_json", fake_get_json)
        monkeypatch.setattr(timeout_manager_module, "_agent_post_form", fake_post_form)
        assert asyncio.run(manager.complete_analysis()) is True
        assert requested["mkdir"] == f"C:\\Temp\\{expected_folder}"

    def test_complete_analysis_returns_false_without_task_id(self, monkeypatch, caplog):
        """Without a task_id, complete_analysis should fail gracefully."""
        manager = timeout_manager_module.SessionTimeoutManager("192.168.56.24", "tester")
        caplog.set_level(logging.ERROR, logger="guac-session")
        assert asyncio.run(manager.complete_analysis()) is False
        assert "No task ID" in caplog.text

    def test_complete_analysis_returns_false_without_vm_ip(self, monkeypatch, caplog):
        """Without a valid VM IP, complete_analysis should fail gracefully."""
        manager = timeout_manager_module.SessionTimeoutManager("unknown", "tester", task_id="999")
        caplog.set_level(logging.ERROR, logger="guac-session")
        assert asyncio.run(manager.complete_analysis()) is False
        assert "No valid VM IP" in caplog.text

    def test_complete_analysis_returns_false_on_http_error(self, monkeypatch, caplog):
        """Non-200 response from agent returns False."""
        manager = timeout_manager_module.SessionTimeoutManager("192.168.56.25", "tester", task_id="888")
        caplog.set_level(logging.WARNING, logger="guac-session")

        async def fake_get_json(vm_ip, path):
            if path == "/environ":
                return {"environ": {"TMP": "/tmp"}}
            if path == "/system":
                return {"system": "Linux"}
            return {}

        async def fake_post_form(vm_ip, path, data):
            return 500

        monkeypatch.setattr(timeout_manager_module, "_agent_get_json", fake_get_json)
        monkeypatch.setattr(timeout_manager_module, "_agent_post_form", fake_post_form)
        assert asyncio.run(manager.complete_analysis()) is False
        assert "HTTP 500" in caplog.text
