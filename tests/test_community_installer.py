"""Tests for the utils/community.py install guards."""

import os
import sys

import pytest

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.constants import CUCKOO_ROOT
from utils import community


@pytest.fixture(autouse=True)
def _reset_core_cache():
    community._CORE_TRACKED_CACHE = community._UNSET
    yield
    community._CORE_TRACKED_CACHE = community._UNSET


@pytest.mark.parametrize(
    "entry, relpath, expected",
    (
        # Documented form: "<category>/<path>".
        ("signatures/my_amazing_signature.py", "my_amazing_signature.py", True),
        # Bare path inside the category folder.
        ("my_amazing_signature.py", "my_amazing_signature.py", True),
        # Nested path keeps its subfolder.
        ("signatures/windows/foo.py", "windows/foo.py", True),
        ("windows/foo.py", "windows/foo.py", True),
        # Unrelated entries must not match.
        ("signatures/other.py", "my_amazing_signature.py", False),
        ("windows/foo.py", "linux/foo.py", False),
    ),
)
def test_is_blocklisted_accepts_the_documented_forms(monkeypatch, entry, relpath, expected):
    monkeypatch.setattr(community, "blocklist", {"signatures": [entry]})
    filepath = os.path.join(CUCKOO_ROOT, "modules/signatures", relpath)
    assert community.is_blocklisted("signatures", relpath, filepath) is expected


def test_is_blocklisted_accepts_an_absolute_entry(monkeypatch):
    filepath = os.path.join(CUCKOO_ROOT, "modules/signatures", "foo.py")
    monkeypatch.setattr(community, "blocklist", {"signatures": [filepath]})
    assert community.is_blocklisted("signatures", "foo.py", filepath) is True


def test_is_blocklisted_empty_category(monkeypatch):
    monkeypatch.setattr(community, "blocklist", {"signatures": []})
    assert community.is_blocklisted("signatures", "foo.py", "/tmp/foo.py") is False
    assert community.is_blocklisted("missing", "foo.py", "/tmp/foo.py") is False


def test_clean_category_is_rooted_at_cuckoo_root(monkeypatch):
    removed = []
    monkeypatch.setattr(community.shutil, "rmtree", removed.append)
    monkeypatch.setattr(community, "path_exists", lambda path: True)

    community.clean_category("modules/machinery")

    # Not the relative path, which would delete relative to the current directory.
    assert removed == [os.path.join(CUCKOO_ROOT, "modules/machinery")]


def test_clean_category_noop_when_absent(monkeypatch):
    removed = []
    monkeypatch.setattr(community.shutil, "rmtree", removed.append)
    monkeypatch.setattr(community, "path_exists", lambda path: False)

    community.clean_category("modules/machinery")

    assert removed == []


def test_shadows_core_file_detects_a_core_path(monkeypatch):
    monkeypatch.setattr(
        community,
        "core_tracked_files",
        lambda: frozenset({os.path.normpath("modules/machinery/virtualbox.py")}),
    )
    assert community.shadows_core_file("modules/machinery", "virtualbox.py") is True
    assert community.shadows_core_file("modules/machinery", "virtualbox_custom.py") is False


def test_shadows_core_file_is_inert_without_git(monkeypatch):
    monkeypatch.setattr(community, "core_tracked_files", lambda: None)
    assert community.shadows_core_file("modules/machinery", "virtualbox.py") is False


def test_core_tracked_files_handles_git_failure(monkeypatch):
    class _Result:
        returncode = 128
        stdout = b""

    monkeypatch.setattr(community.subprocess, "run", lambda *a, **kw: _Result())
    assert community.core_tracked_files() is None


def test_core_tracked_files_parses_nul_separated_output(monkeypatch):
    class _Result:
        returncode = 0
        stdout = b"modules/machinery/virtualbox.py\0modules/signatures/foo.py\0"

    calls = []

    def _run(*args, **kwargs):
        calls.append(args)
        return _Result()

    monkeypatch.setattr(community.subprocess, "run", _run)

    tracked = community.core_tracked_files()
    assert tracked == frozenset({"modules/machinery/virtualbox.py", "modules/signatures/foo.py"})

    # Cached: a second call must not spawn git again.
    community.core_tracked_files()
    assert len(calls) == 1


def test_core_tracked_files_survives_missing_git(monkeypatch):
    def _run(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(community.subprocess, "run", _run)
    assert community.core_tracked_files() is None


def _make_tarball(tmp_path, relpath, payload=b"community version\n", mode=None):
    import io
    import tarfile

    src = tmp_path / "src" / "community-master" / os.path.dirname(relpath)
    src.mkdir(parents=True, exist_ok=True)
    (tmp_path / "src" / "community-master" / relpath).write_bytes(payload)

    def _set_mode(tarinfo):
        if mode is not None and tarinfo.name == f"community-master/{relpath}":
            tarinfo.mode = mode
        return tarinfo

    archive = tmp_path / "community.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(tmp_path / "src" / "community-master", arcname="community-master", filter=_set_mode)
    assert io  # keep the import meaningful for linters
    return str(archive)


@pytest.mark.parametrize("shadow_core, expected", ((False, b"core version\n"), (True, b"community version\n")))
def test_install_refuses_to_replace_a_core_file_without_shadow_core(monkeypatch, tmp_path, shadow_core, expected):
    relpath = "modules/machinery/virtualbox.py"
    archive = _make_tarball(tmp_path, relpath)

    root = tmp_path / "root"
    (root / "modules" / "machinery").mkdir(parents=True)
    target = root / relpath
    target.write_bytes(b"core version\n")

    monkeypatch.setattr(community, "CUCKOO_ROOT", str(root))
    monkeypatch.setattr(community, "core_tracked_files", lambda: frozenset({os.path.normpath(relpath)}))
    monkeypatch.setattr(community, "blocklist", {})

    community.install(
        ["machinery"],
        force=True,
        rewrite=True,
        filepath=archive,
        shadow_core=shadow_core,
    )

    assert target.read_bytes() == expected


def test_install_still_writes_files_that_are_not_core(monkeypatch, tmp_path):
    relpath = "modules/machinery/virtualbox_custom.py"
    archive = _make_tarball(tmp_path, relpath)

    root = tmp_path / "root"
    (root / "modules" / "machinery").mkdir(parents=True)

    monkeypatch.setattr(community, "CUCKOO_ROOT", str(root))
    monkeypatch.setattr(community, "core_tracked_files", lambda: frozenset({"modules/machinery/virtualbox.py"}))
    monkeypatch.setattr(community, "blocklist", {})

    community.install(["machinery"], force=True, rewrite=True, filepath=archive)

    assert (root / relpath).read_bytes() == b"community version\n"


def test_shadow_core_implies_rewrite_for_core_paths(monkeypatch, tmp_path):
    relpath = "modules/machinery/virtualbox.py"
    archive = _make_tarball(tmp_path, relpath)

    root = tmp_path / "root"
    (root / "modules" / "machinery").mkdir(parents=True)
    target = root / relpath
    target.write_bytes(b"core version\n")

    monkeypatch.setattr(community, "CUCKOO_ROOT", str(root))
    monkeypatch.setattr(community, "core_tracked_files", lambda: frozenset({os.path.normpath(relpath)}))
    monkeypatch.setattr(community, "blocklist", {})

    community.install(
        ["machinery"],
        force=True,
        rewrite=False,
        filepath=archive,
        shadow_core=True,
    )

    assert target.read_bytes() == b"community version\n"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
def test_install_preserves_executable_mode_on_fresh_and_rewrite(monkeypatch, tmp_path):
    relpath = "data/7zz"
    archive = _make_tarball(tmp_path, relpath, payload=b"\x7fELF...", mode=0o755)

    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    target = root / relpath

    monkeypatch.setattr(community, "CUCKOO_ROOT", str(root))
    monkeypatch.setattr(community, "core_tracked_files", lambda: frozenset())
    monkeypatch.setattr(community, "blocklist", {})

    # Fresh install sets 0755.
    community.install(["data"], force=True, rewrite=False, filepath=archive)
    assert target.read_bytes() == b"\x7fELF..."
    assert (target.stat().st_mode & 0o777) == 0o755

    # Existing 0644 file gets upgraded to 0755 on --rewrite.
    target.chmod(0o644)
    community.install(["data"], force=True, rewrite=True, filepath=archive)
    assert (target.stat().st_mode & 0o777) == 0o755


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
def test_install_clears_stale_exec_bits_when_archive_member_is_not_executable(monkeypatch, tmp_path):
    relpath = "modules/signatures/foo.py"
    archive = _make_tarball(tmp_path, relpath, payload=b"# signature\n", mode=0o644)

    root = tmp_path / "root"
    (root / "modules" / "signatures").mkdir(parents=True)
    target = root / relpath
    target.write_bytes(b"old\n")
    target.chmod(0o755)

    monkeypatch.setattr(community, "CUCKOO_ROOT", str(root))
    monkeypatch.setattr(community, "core_tracked_files", lambda: frozenset())
    monkeypatch.setattr(community, "blocklist", {})

    community.install(["signatures"], force=True, rewrite=True, filepath=archive)
    assert target.read_bytes() == b"# signature\n"
    assert (target.stat().st_mode & 0o111) == 0


def test_install_skips_non_regular_tar_member_without_truncating_existing_file(monkeypatch, tmp_path):
    import io
    import tarfile

    archive = tmp_path / "symlink.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        root_dir = tarfile.TarInfo("community-master/data")
        root_dir.type = tarfile.DIRTYPE
        tar.addfile(root_dir)
        link = tarfile.TarInfo("community-master/data/7zz")
        link.type = tarfile.SYMTYPE
        link.linkname = "/bin/sh"
        tar.addfile(link, io.BytesIO(b""))

    root = tmp_path / "root"
    (root / "data").mkdir(parents=True)
    target = root / "data" / "7zz"
    target.write_bytes(b"existing binary")

    monkeypatch.setattr(community, "CUCKOO_ROOT", str(root))
    monkeypatch.setattr(community, "core_tracked_files", lambda: frozenset())
    monkeypatch.setattr(community, "blocklist", {})

    community.install(["data"], force=True, rewrite=True, filepath=str(archive))
    assert target.read_bytes() == b"existing binary"


def test_install_retries_transient_non_gzip_download(monkeypatch, tmp_path):
    relpath = "data/mitre/TTPs.json"
    archive = _make_tarball(tmp_path, relpath, payload=b"{}")
    valid_bytes = open(archive, "rb").read()

    responses = [
        type("_Resp", (), {"status": 502, "data": b"<html>502 Bad Gateway</html>"})(),
        type("_Resp", (), {"status": 200, "data": valid_bytes})(),
    ]

    class _FakeHTTP:
        def request(self, method, url, headers=None):
            return responses.pop(0)

    root = tmp_path / "root"
    monkeypatch.setattr(community, "CUCKOO_ROOT", str(root))
    monkeypatch.setattr(community, "core_tracked_files", lambda: frozenset())
    monkeypatch.setattr(community, "blocklist", {})
    monkeypatch.setattr(community, "_http_client", lambda proxy=None: _FakeHTTP())
    monkeypatch.setattr(community.time, "sleep", lambda _: None)

    community.install(["mitre"], force=True, rewrite=True, url="https://github.com/kevoreilly/community/archive/master.tar.gz")
    assert (root / "data" / "mitre" / "TTPs.json").read_bytes() == b"{}"
    assert responses == []

