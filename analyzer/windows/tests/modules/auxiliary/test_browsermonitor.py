"""Tests for the browser extension monitor (extra/browser_extension)."""

import json
import logging
from types import SimpleNamespace
from unittest import mock

import pytest

from modules.auxiliary import browsermonitor
from modules.auxiliary.browsermonitor import Browsermonitor

REQUESTS = [{"url": "http://example.com/", "method": "GET"}]


@pytest.fixture
def temp_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(browsermonitor.tempfile, "gettempdir", lambda: str(tmp_path))
    return tmp_path


@pytest.fixture
def upload(monkeypatch):
    upload_mock = mock.Mock()
    monkeypatch.setattr(browsermonitor, "upload_buffer_to_host", upload_mock)
    monkeypatch.setattr(browsermonitor, "FINAL_READ_DELAY", 0)
    return upload_mock


def make_monitor(package="firefox_ext", enabled=True):
    return Browsermonitor(config=SimpleNamespace(browsermonitor=enabled, package=package))


def write_log(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(content, bytes):
        content = json.dumps(content).encode()
    path.write_bytes(content)
    return path


def uploaded_requests(upload):
    upload.assert_called_once()
    buffer, dump_path = upload.call_args.args
    assert dump_path == "browser/requests.log"
    return json.loads(buffer)


class TestBrowsermonitor:
    def test_log_in_random_agent_folder(self, temp_dir, upload):
        """Agents >= 0.20 create the folder with mkdtemp(prefix=""), so its name does not start with "tmp"."""
        monitor = make_monitor()
        write_log(temp_dir / "x8k2n4qa" / "bext_abcdefghijk.json", REQUESTS)
        monitor._poll()
        monitor.stop()
        assert uploaded_requests(upload) == REQUESTS

    def test_tor_browser_log_in_temp(self, temp_dir, upload):
        monitor = make_monitor(package="tor_browser")
        write_log(temp_dir / "bext_default.json", REQUESTS)
        monitor.stop()
        assert uploaded_requests(upload) == REQUESTS

    def test_keeps_last_complete_json(self, temp_dir, upload):
        monitor = make_monitor()
        log_path = write_log(temp_dir / "x8k2n4qa" / "bext_abcdefghijk.json", REQUESTS)
        monitor._poll()
        # The agent is rewriting the file when the analysis ends.
        write_log(log_path, b'[{"url": "http://example.com/", "method": "GET"}, {"url": "http://exa')
        monitor.stop()
        assert uploaded_requests(upload) == REQUESTS

    def test_ansi_encoded_log(self, temp_dir, upload):
        """Agents < 0.23 write the log with the ANSI code page."""
        monitor = make_monitor()
        write_log(temp_dir / "x8k2n4qa" / "bext_abcdefghijk.json", b'[{"url": "http://example.com/caf\xe9"}]')
        monitor.stop()
        assert uploaded_requests(upload) == [{"url": "http://example.com/caf\u00e9"}]

    def test_ignores_unchanged_log_from_snapshot(self, temp_dir, upload):
        write_log(temp_dir / "x8k2n4qa" / "bext_abcdefghijk.json", REQUESTS)
        monitor = make_monitor()
        monitor.stop()
        upload.assert_not_called()

    def test_snapshot_log_updated_during_analysis(self, temp_dir, upload):
        log_path = write_log(temp_dir / "x8k2n4qa" / "bext_abcdefghijk.json", REQUESTS)
        monitor = make_monitor()
        requests = REQUESTS + [{"url": "http://example.com/script.js", "method": "GET"}]
        write_log(log_path, requests)
        monitor.stop()
        assert uploaded_requests(upload) == requests

    def test_uploads_once(self, temp_dir, upload):
        monitor = make_monitor()
        write_log(temp_dir / "x8k2n4qa" / "bext_abcdefghijk.json", REQUESTS)
        monitor.stop()
        monitor.stop()
        upload.assert_called_once()

    def test_thread_stops(self, temp_dir, upload):
        monitor = make_monitor()
        monitor.start()
        write_log(temp_dir / "x8k2n4qa" / "bext_abcdefghijk.json", REQUESTS)
        monitor.stop()
        monitor.join(timeout=5)
        assert not monitor.is_alive()
        assert uploaded_requests(upload) == REQUESTS

    def test_no_log(self, temp_dir, upload, caplog):
        monitor = make_monitor()
        with caplog.at_level(logging.WARNING):
            monitor.stop()
        upload.assert_not_called()
        assert "No browser extension log found" in caplog.text

    def test_no_log_without_browser_package(self, temp_dir, upload, caplog):
        monitor = make_monitor(package="exe")
        with caplog.at_level(logging.WARNING):
            monitor.stop()
        upload.assert_not_called()
        assert "No browser extension log found" not in caplog.text

    def test_disabled(self, temp_dir, upload):
        monitor = make_monitor(enabled=False)
        write_log(temp_dir / "x8k2n4qa" / "bext_abcdefghijk.json", REQUESTS)
        monitor.run()
        monitor.stop()
        upload.assert_not_called()
