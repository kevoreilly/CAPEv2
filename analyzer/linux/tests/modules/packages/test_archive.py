import stat
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from lib.common import abstracts
from modules.packages import archive


@pytest.fixture
def prepare_archive(monkeypatch, tmp_path):
    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setenv("TEMP", str(tmp_path))

    def prepare(members, options=None):
        package = archive.Archive(options=options or {})
        package.execute = Mock(return_value=4242)
        package.get_path_app_in_path = Mock(return_value="/usr/bin/7z")

        def extract(binary, source, root, password, multiple_passwords):
            for name, contents in members.items():
                target = Path(root, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
                target.chmod(0o640)

        extraction = Mock(side_effect=extract)
        upload = Mock()
        monkeypatch.setattr(archive, "extract_archive", extraction)
        monkeypatch.setattr(archive, "upload_extracted_files", upload)
        return package, extraction, upload

    return prepare


def test_recursive_classification_ignores_archive_words_in_paths(prepare_archive, monkeypatch, tmp_path):
    file_binary = shutil.which("file")
    if file_binary is None:
        pytest.skip("file is required for recursive classification")
    package, extraction, upload = prepare_archive({"run.sh": b"echo safe\n"}, {"recursion_depth": 1})
    package.get_path_app_in_path.side_effect = lambda name: file_binary if name == "file" else "/usr/bin/7z"
    try:
        assert package.start(str(tmp_path / "archive-compressed-image.zip")) == [4242]
        assert extraction.call_count == 1
        assert upload.call_args.args[1] == ["run.sh"]
    finally:
        package.finish()

def test_private_extraction_lives_until_finish(prepare_archive, tmp_path):
    package, extraction, _ = prepare_archive({"nested/run.sh": b"echo safe", "README": b"documentation"})
    package.start(str(tmp_path / "sample.zip"))
    root = Path(extraction.call_args.args[2])
    assert root.parent == tmp_path
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert (root / "nested/run.sh").exists()
    assert (root / "README").exists()
    assert package.finish() is True
    assert not root.exists()


def test_same_named_archives_have_isolated_lifecycles(prepare_archive, tmp_path):
    first, extraction, _ = prepare_archive({"run.sh": b"echo safe"})
    first.start(str(tmp_path / "same.zip"))
    first_root = Path(extraction.call_args.args[2])
    second, extraction, _ = prepare_archive({"run.sh": b"echo safe"})
    second.start(str(tmp_path / "same.zip"))
    second_root = Path(extraction.call_args.args[2])
    assert first_root != second_root
    first.finish()
    assert second_root.exists()
    second.finish()


def test_failed_start_cleans_extraction(prepare_archive, tmp_path):
    package, extraction, _ = prepare_archive({})
    extraction.side_effect = RuntimeError("failed extraction")
    with pytest.raises(RuntimeError, match="failed extraction"):
        package.start(str(tmp_path / "sample.zip"))
    assert not Path(extraction.call_args.args[2]).exists()


def test_failed_finish_cleans_extraction(prepare_archive, tmp_path):
    package, extraction, _ = prepare_archive({"run.sh": b"echo safe"})
    package.start(str(tmp_path / "sample.zip"))
    root = Path(extraction.call_args.args[2])
    package.nc.close.side_effect = RuntimeError("closed connection")
    with pytest.raises(RuntimeError, match="closed connection"):
        package.finish()
    assert not root.exists()


@pytest.mark.parametrize("available, expected", [
    ({"/usr/bin/7z", "/usr/bin/7zz"}, "/usr/bin/7z"),
    ({"/usr/bin/7zz"}, "/usr/bin/7zz"),
])
def test_archive_discovers_7zip(prepare_archive, monkeypatch, tmp_path, available, expected):
    package, extraction, _ = prepare_archive({"run.sh": b"echo safe"})
    del package.get_path_app_in_path
    try:
        with monkeypatch.context() as discovery:
            discovery.setattr(abstracts.os.path, "isfile", lambda path: path in available)
            assert package.start(str(tmp_path / "sample.zip")) == [4242]
        assert extraction.call_args.args[0] == expected
    finally:
        package.finish()


@pytest.mark.skipif(sys.platform != "linux", reason="Analyzer requires Linux")
@pytest.mark.parametrize("members, expected", [
    ({"README": b"documentation", "run.sh": b"echo safe"}, {4242}),
    ({"README": b"documentation"}, set()),
])
def test_archive_results_register_with_pid_consumer(prepare_archive, monkeypatch, tmp_path, members, expected):
    import analyzer

    monkeypatch.setattr(analyzer, "PROCESS_LIST", set())
    monkeypatch.setattr(analyzer, "SEEN_LIST", set())
    package, _, _ = prepare_archive(members)
    try:
        analyzer.add_pids(package.start(str(tmp_path / "sample.zip")))
        assert analyzer.PROCESS_LIST == expected
        assert analyzer.SEEN_LIST == expected
    finally:
        package.finish()


@pytest.mark.parametrize("kind, name", [
    ("script", "nested/RUN.SH"),
    ("elf", "nested/payload.unusual"),
])
def test_discovery_dispatches_payloads_beside_readme(prepare_archive, tmp_path, kind, name):
    if kind == "elf" and sys.platform != "linux":
        pytest.skip("Requires an ELF Python interpreter")
    contents = b"printf 'two words\\n'" if kind == "script" else Path(sys.executable).read_bytes()
    package, extraction, _ = prepare_archive(
        {"README": b"documentation", name: contents},
        {"arguments": "-c \"print('two words')\""},
    )
    outputs = []
    launched = []

    def execute(command):
        child = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = child.communicate(timeout=5)
            assert child.returncode == 0, stderr
            outputs.append(stdout)
            launched.append(child.pid)
            return child.pid
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()

    package.execute = execute
    try:
        assert package.start(str(tmp_path / "sample.zip")) == launched
        assert len(launched) == 1
        assert outputs == [b"two words\n"]
        mode = Path(extraction.call_args.args[2], name).stat().st_mode
        assert stat.S_IMODE(mode) == (0o740 if kind == "elf" else 0o640)
    finally:
        package.finish()


def test_empty_extraction_is_reported_and_cleaned(prepare_archive, tmp_path):
    package, extraction, _ = prepare_archive({})
    with pytest.raises(archive.CuckooPackageError, match="Empty archive"):
        package.start(str(tmp_path / "sample.zip"))
    assert not Path(extraction.call_args.args[2]).exists()


def test_archive_file_option_unsupported_or_missing_returns_empty_list(prepare_archive, tmp_path):
    package, _, _ = prepare_archive({"README": b"documentation"}, {"file": "README"})
    try:
        assert package.start(str(tmp_path / "sample.zip")) == []
    finally:
        package.finish()


def test_archive_skips_external_symlinks_in_discovery_and_upload(prepare_archive, monkeypatch, tmp_path):
    outside = tmp_path / "outside.sh"
    outside.write_text("echo outside")
    package, extraction, upload = prepare_archive({"run.sh": b"echo safe"})

    orig_side_effect = extraction.side_effect

    def extract_with_symlink(binary, source, root, password, multiple_passwords):
        orig_side_effect(binary, source, root, password, multiple_passwords)
        (Path(root) / "escape.sh").symlink_to(outside)

    extraction.side_effect = extract_with_symlink
    try:
        assert package.start(str(tmp_path / "sample.zip")) == [4242]
        assert upload.call_args.args[1] == ["run.sh"]
    finally:
        package.finish()


def test_archive_recursion_cleans_failed_nested_dir_and_handles_non_utf8(prepare_archive, monkeypatch, tmp_path):
    package, extraction, _ = prepare_archive(
        {"image.png": b"fake-png", "run.sh": b"echo safe"},
        {"recursion_depth": 1},
    )
    package.get_path_app_in_path.side_effect = lambda name: "/usr/bin/file" if name == "file" else "/usr/bin/7z"

    orig_extract = extraction.side_effect

    def extract_top_only(binary, source, root, password, multiple_passwords):
        if Path(source).name == "image.png":
            raise archive.CuckooPackageError("not an archive")
        orig_extract(binary, source, root, password, multiple_passwords)

    extraction.side_effect = extract_top_only

    def fake_run(cmd, **kwargs):
        assert kwargs.get("errors") == "replace"
        res = Mock()
        res.stdout = "PNG Image data\n" if cmd[-1].endswith("image.png") else "ASCII text\n"
        return res

    monkeypatch.setattr(archive.subprocess, "run", fake_run)
    try:
        assert package.start(str(tmp_path / "sample.zip")) == [4242]
        root = Path(package._extraction_dir.name)
        assert list(root.glob("nested-*")) == []
    finally:
        package.finish()


def test_extract_archive_empty_password_defaults_to_infected_and_reads_stdout_error(monkeypatch, tmp_path):
    from lib.common import zip_utils

    seen_args = []

    def fake_run(cmd, **kwargs):
        seen_args.append(cmd)
        res = Mock()
        res.returncode = 2
        res.stderr = b""
        res.stdout = b"ERROR: Can not open the file as archive\n"
        return res

    monkeypatch.setattr(zip_utils.subprocess, "run", fake_run)
    with pytest.raises(archive.CuckooPackageError, match="Can not open the file as archive"):
        zip_utils.extract_archive("/usr/bin/7z", str(tmp_path / "bad.7z"), str(tmp_path), password="")
    assert "-pinfected" in seen_args[0]


def test_extract_archive_tolerates_nonzero_exit_when_files_extracted(monkeypatch, tmp_path):
    from lib.common import zip_utils

    extract_dir = tmp_path / "out"
    extract_dir.mkdir()

    def fake_run(cmd, **kwargs):
        (extract_dir / "payload.sh").write_bytes(b"echo ok\n")
        res = Mock()
        res.returncode = 1
        res.stderr = b"WARNING: There are some data after the end of the payload data\n"
        res.stdout = b""
        return res

    monkeypatch.setattr(zip_utils.subprocess, "run", fake_run)
    zip_utils.extract_archive("/usr/bin/7z", str(tmp_path / "sample.run"), str(extract_dir))
    assert (extract_dir / "payload.sh").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Requires ELF Python binary")
def test_archive_skips_shared_libraries_and_caps_max_executables(prepare_archive, tmp_path):
    elf_bytes = Path(sys.executable).read_bytes()
    members = {
        "libfoo.so": elf_bytes,
        "libbar.so.1.2": elf_bytes,
        "mod.ko": elf_bytes,
        "s1.sh": b"echo 1\n",
        "s2.sh": b"echo 2\n",
        "s3.sh": b"echo 3\n",
    }
    package, _, _ = prepare_archive(members, {"max_executables": 2})
    executed = []

    def track_exec(cmd):
        executed.append(cmd)
        return 1000 + len(executed)

    package.execute = track_exec
    try:
        pids = package.start(str(tmp_path / "bundle.zip"))
        assert pids == [1001, 1002]
        assert len(executed) == 2
        assert all(".so" not in cmd and ".ko" not in cmd for cmd in executed)
    finally:
        package.finish()

