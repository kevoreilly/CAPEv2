import hashlib
import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from modules.auxiliary import filecollector


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_filecollector_collects_created_and_nested_files(tmp_path):
    uploaded = []

    def fake_upload(src, dst):
        uploaded.append((src, dst))

    watch_dir = tmp_path / "watched"
    watch_dir.mkdir()
    cfg = SimpleNamespace(filecollector=True)

    with (
        patch.object(filecollector, "upload_to_host", side_effect=fake_upload),
        patch.object(filecollector, "_POLL_TIMEOUT_SEC", 0.05),
        patch.object(filecollector, "_STOP_DELAY_SEC", 0),
    ):
        collector = filecollector.FileCollector({}, cfg, watch_roots=[str(watch_dir)])
        assert collector.initComplete is True
        collector.start()

        first = watch_dir / "dropped.bin"
        payload = b"payload-one"
        first.write_bytes(payload)

        # Duplicate content should be skipped.
        dup = watch_dir / "duplicate.bin"
        dup.write_bytes(payload)

        # strace.log should be ignored.
        (watch_dir / "strace.log").write_text("ignored")

        # Immediately create a subdirectory and write a file inside it to exercise
        # the inotify new-directory race window before the subdirectory watch attaches.
        nested_dir = watch_dir / "sub"
        nested_dir.mkdir()
        second = nested_dir / "nested.bin"
        nested_payload = b"payload-two"
        second.write_bytes(nested_payload)

        expected_h1 = os.path.join("files", hashlib.sha256(payload).hexdigest())
        expected_h2 = os.path.join("files", hashlib.sha256(nested_payload).hexdigest())
        ignored_h = os.path.join("files", hashlib.sha256(b"ignored").hexdigest())

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            dsts = {dst for _, dst in uploaded}
            if expected_h1 in dsts and expected_h2 in dsts:
                break
            time.sleep(0.02)

        collector.stop()

    uploaded_dsts = [dst for _, dst in uploaded]
    assert expected_h1 in uploaded_dsts
    assert expected_h2 in uploaded_dsts
    assert uploaded_dsts.count(expected_h1) == 1
    assert ignored_h not in uploaded_dsts
    assert all("strace.log" not in src for src, _ in uploaded)


def test_filecollector_init_does_not_hang_when_inotify_unavailable():
    cfg = SimpleNamespace(filecollector=True)
    with (
        patch.object(filecollector, "HAVE_INOTIFY", False),
        patch.object(filecollector, "_STOP_DELAY_SEC", 0),
    ):
        collector = filecollector.FileCollector({}, cfg)
        assert collector.initComplete is True
        assert collector.do_run is False
        collector.stop()


def test_filecollector_disabled_does_not_spawn_thread():
    cfg = SimpleNamespace(filecollector=False)
    collector = filecollector.FileCollector({}, cfg)
    assert collector.thread is None
    assert collector.start() is False
    assert collector.stop() is False
