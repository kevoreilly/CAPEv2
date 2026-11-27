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


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_native_inotify_watcher_rename_recreate_and_symlink_skip(tmp_path):
    watcher = filecollector.NativeInotifyWatcher()
    try:
        root = tmp_path / "root"
        root.mkdir()
        target = tmp_path / "outside"
        target.mkdir()

        # Directory symlink must be skipped and must not clobber watches.
        link_dir = root / "link_to_outside"
        link_dir.symlink_to(target)
        watcher.add_watch(str(root), rec=True)
        assert str(link_dir) not in watcher._path_to_wd
        assert str(target) not in watcher._path_to_wd

        # Renaming a watched directory and recreating the original path must evict
        # the stale path->wd mapping so the recreated inode receives a fresh watch.
        orig = root / "dir_a"
        renamed = root / "dir_b"
        orig.mkdir()
        assert watcher._add_single_watch(str(orig), filecollector._WATCH_MASK) is True
        old_wd = watcher._path_to_wd[str(orig)]

        orig.rename(renamed)
        assert watcher._add_single_watch(str(renamed), filecollector._WATCH_MASK) is True
        assert watcher._path_to_wd[str(renamed)] == old_wd
        assert str(orig) not in watcher._path_to_wd

        orig.mkdir()
        assert watcher._add_single_watch(str(orig), filecollector._WATCH_MASK) is True
        new_wd = watcher._path_to_wd[str(orig)]
        assert new_wd != old_wd
        assert watcher._wd_to_path[new_wd] == str(orig)
        assert watcher._wd_to_path[old_wd] == str(renamed)
    finally:
        watcher.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_filecollector_setup_watches_resolves_usrmerge_top_level_symlinks(tmp_path):
    fake_root = tmp_path / "sysroot"
    (fake_root / "usr" / "bin" / "nested").mkdir(parents=True)
    (fake_root / "usr" / "sbin").mkdir(parents=True)
    (fake_root / "usr" / "lib" / "systemd" / "system").mkdir(parents=True)
    (fake_root / "usr" / "share").mkdir(parents=True)
    (fake_root / "etc" / "conf.d").mkdir(parents=True)
    (fake_root / "proc" / "1").mkdir(parents=True)

    # Top-level usrmerge symlinks (unignored: bin, sbin; duplicate target: sbin_alias; ignored: lib)
    (fake_root / "bin").symlink_to("usr/bin")
    (fake_root / "sbin").symlink_to("usr/sbin")
    (fake_root / "sbin_alias").symlink_to("usr/bin")
    (fake_root / "lib").symlink_to("usr/lib")
    # Symlinks pointing to root, ignored root, or pseudo-fs subtree must not be watched recursively
    (fake_root / "loop_root").symlink_to(".")
    (fake_root / "link_usr").symlink_to("usr")
    (fake_root / "link_proc_sub").symlink_to("proc/1")
    # Symlink below a watched root must still be skipped
    (fake_root / "etc" / "link_share").symlink_to("../usr/share")

    cfg = SimpleNamespace(filecollector=False)
    collector = filecollector.FileCollector({}, cfg)
    watcher = filecollector.NativeInotifyWatcher()
    try:
        collector._setup_watches(watcher, root_dir=str(fake_root))
        watched = set(watcher._path_to_wd.keys())

        assert os.path.realpath(str(fake_root)) in watched
        assert os.path.realpath(str(fake_root / "usr" / "bin")) in watched
        assert os.path.realpath(str(fake_root / "usr" / "bin" / "nested")) in watched
        assert os.path.realpath(str(fake_root / "usr" / "sbin")) in watched
        assert os.path.realpath(str(fake_root / "etc")) in watched
        assert os.path.realpath(str(fake_root / "etc" / "conf.d")) in watched

        # Ignored trees and symlinks below roots remain unwatched
        assert os.path.realpath(str(fake_root / "usr")) not in watched
        assert os.path.realpath(str(fake_root / "usr" / "lib")) not in watched
        assert os.path.realpath(str(fake_root / "usr" / "lib" / "systemd" / "system")) not in watched
        assert os.path.realpath(str(fake_root / "usr" / "share")) not in watched
        assert os.path.realpath(str(fake_root / "proc")) not in watched
        assert os.path.realpath(str(fake_root / "proc" / "1")) not in watched
    finally:
        watcher.close()

    # Explicit watch_roots pointing at a top-level symlink also resolves and watches the target.
    collector_explicit = filecollector.FileCollector({}, cfg, watch_roots=[str(fake_root / "bin")])
    watcher_explicit = filecollector.NativeInotifyWatcher()
    try:
        collector_explicit._setup_watches(watcher_explicit)
        watched_explicit = set(watcher_explicit._path_to_wd.keys())
        assert os.path.realpath(str(fake_root / "usr" / "bin")) in watched_explicit
        assert os.path.realpath(str(fake_root / "usr" / "bin" / "nested")) in watched_explicit
    finally:
        watcher_explicit.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_native_inotify_watcher_move_out_and_recreate_replaces_watch(tmp_path):
    watcher = filecollector.NativeInotifyWatcher()
    try:
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        sub = root / "target"
        sub.mkdir()

        watcher.add_watch(str(root), rec=True)
        old_wd = watcher._path_to_wd[str(sub)]

        # Move the watched directory outside the watched root (no IN_IGNORED emitted),
        # then recreate the same path as a new inode and drop a file inside it.
        sub.rename(outside / "target")
        sub.mkdir()
        (sub / "early.bin").write_bytes(b"early")

        seen_paths = set()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            for _, p in watcher.read_events(timeout=0.05):
                seen_paths.add(p)
            if str(sub / "early.bin") in seen_paths and watcher._path_to_wd.get(str(sub)) != old_wd:
                break

        new_wd = watcher._path_to_wd.get(str(sub))
        assert new_wd is not None
        assert new_wd != old_wd
        assert old_wd not in watcher._wd_to_path

        # Subsequent writes inside the recreated directory must also emit events on the new watch.
        late_file = sub / "late.bin"
        late_file.write_bytes(b"late")
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and str(late_file) not in seen_paths:
            for _, p in watcher.read_events(timeout=0.05):
                seen_paths.add(p)
        assert str(late_file) in seen_paths
    finally:
        watcher.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_native_inotify_watcher_overwrite_rename_keeps_active_watch_across_ignored(tmp_path):
    watcher = filecollector.NativeInotifyWatcher()
    try:
        root = tmp_path / "root"
        root.mkdir()
        dir_a = root / "dir_a"
        dir_b = root / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()

        watcher.add_watch(str(root), rec=True)
        wd_a = watcher._path_to_wd[str(dir_a)]
        wd_b = watcher._path_to_wd[str(dir_b)]
        assert wd_a != wd_b

        # Overwrite empty dir_a with dir_b; kernel queues IN_MOVED_TO for dir_a and IN_IGNORED for wd_a.
        dir_b.rename(dir_a)

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            watcher.read_events(timeout=0.05)
            if watcher._path_to_wd.get(str(dir_a)) == wd_b and str(dir_b) not in watcher._path_to_wd:
                break

        # Drain any trailing IN_IGNORED event for wd_a and confirm it does not clobber dir_a -> wd_b.
        watcher.read_events(timeout=0.05)
        assert watcher._path_to_wd.get(str(dir_a)) == wd_b
        assert watcher._wd_to_path.get(wd_b) == str(dir_a)
        assert str(dir_b) not in watcher._path_to_wd
        assert wd_a not in watcher._wd_to_path

        dropped = dir_a / "after_overwrite.bin"
        dropped.write_bytes(b"payload")
        seen = set()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and str(dropped) not in seen:
            for _, p in watcher.read_events(timeout=0.05):
                seen.add(p)
        assert str(dropped) in seen
    finally:
        watcher.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_native_inotify_watcher_passes_in_onlydir_and_rejects_non_directory(tmp_path):
    regular_file = tmp_path / "plain.txt"
    regular_file.write_text("hello")

    watcher = filecollector.NativeInotifyWatcher()
    try:
        assert watcher._add_single_watch(str(regular_file), filecollector._WATCH_MASK) is False
        assert str(regular_file) not in watcher._path_to_wd

        captured_masks = []
        orig_add = filecollector._LIBC.inotify_add_watch

        def spy_add(fd, path_bytes, mask):
            captured_masks.append(mask)
            return orig_add(fd, path_bytes, mask)

        target_dir = tmp_path / "dir_check"
        target_dir.mkdir()
        with patch.object(filecollector._LIBC, "inotify_add_watch", side_effect=spy_add):
            assert watcher._add_single_watch(str(target_dir), filecollector._WATCH_MASK) is True
        assert len(captured_masks) == 1
        assert captured_masks[0] & filecollector.IN_ONLYDIR
        assert captured_masks[0] & filecollector.IN_DONT_FOLLOW
    finally:
        watcher.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_native_inotify_watcher_uses_poll_and_closes_on_pollnval_and_ebadf(caplog):
    import errno as errno_mod
    import select

    class _FakePoller:
        def __init__(self, result):
            self._result = result
            self.registered = []

        def register(self, fd, eventmask):
            self.registered.append((fd, eventmask))

        def poll(self, timeout_ms):
            return self._result

    # POLLNVAL closes watcher cleanly and stops FileCollector loop without spinning.
    watcher = filecollector.NativeInotifyWatcher()
    fd = watcher._fd
    poller = _FakePoller([(fd, select.POLLNVAL)])
    with (
        patch.object(filecollector.select, "poll", return_value=poller),
        caplog.at_level("WARNING", logger=filecollector.__name__),
    ):
        assert watcher.read_events(timeout=0.1) == []
    assert watcher.is_closed is True
    assert poller.registered == [(fd, select.POLLIN)]
    assert any("error events" in rec.message for rec in caplog.records)

    # EBADF from os.read closes watcher cleanly.
    caplog.clear()
    watcher2 = filecollector.NativeInotifyWatcher()
    fd2 = watcher2._fd
    poller2 = _FakePoller([(fd2, select.POLLIN)])
    with (
        patch.object(filecollector.select, "poll", return_value=poller2),
        patch.object(filecollector.os, "read", side_effect=OSError(errno_mod.EBADF, "Bad file descriptor")),
        caplog.at_level("WARNING", logger=filecollector.__name__),
    ):
        assert watcher2.read_events(timeout=0.1) == []
    assert watcher2.is_closed is True
    assert any("EBADF" in rec.message for rec in caplog.records)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_native_inotify_watcher_warns_on_queue_overflow(tmp_path, caplog):
    import select

    class _ReadyPoller:
        def register(self, fd, eventmask):
            self.fd = fd

        def poll(self, timeout_ms):
            return [(self.fd, select.POLLIN)]

    watcher = filecollector.NativeInotifyWatcher()
    try:
        watch_dir = tmp_path / "ovf"
        watch_dir.mkdir()
        watcher.add_watch(str(watch_dir))
        wd = watcher._path_to_wd[str(watch_dir)]

        overflow_ev = filecollector._EVENT_HEADER.pack(-1, filecollector.IN_Q_OVERFLOW, 0, 0)
        name_bytes = b"kept.bin\x00\x00\x00\x00"
        normal_ev = filecollector._EVENT_HEADER.pack(wd, filecollector.IN_CREATE, 0, len(name_bytes)) + name_bytes

        with (
            patch.object(filecollector.select, "poll", return_value=_ReadyPoller()),
            patch.object(filecollector.os, "read", return_value=overflow_ev + normal_ev),
            caplog.at_level("WARNING", logger=filecollector.__name__),
        ):
            events = watcher.read_events(timeout=0.1)

        assert events == [(filecollector.IN_CREATE, os.path.join(str(watch_dir), "kept.bin"))]
        assert any("overflowed" in rec.message for rec in caplog.records)
    finally:
        watcher.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_filecollector_run_exits_when_watcher_closes_on_pollnval(tmp_path):
    import select

    class _InvalidPoller:
        def register(self, fd, eventmask):
            self.fd = fd

        def poll(self, timeout_ms):
            return [(self.fd, select.POLLNVAL)]

    watch_dir = tmp_path / "watch"
    watch_dir.mkdir()
    cfg = SimpleNamespace(filecollector=True)

    with (
        patch.object(filecollector.select, "poll", return_value=_InvalidPoller()),
        patch.object(filecollector, "_POLL_TIMEOUT_SEC", 0.05),
        patch.object(filecollector, "_STOP_DELAY_SEC", 0),
    ):
        collector = filecollector.FileCollector({}, cfg, watch_roots=[str(watch_dir)])
        assert collector.initComplete is True
        collector.thread.join(timeout=2.0)
        assert not collector.thread.is_alive()
        collector.stop()
