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
