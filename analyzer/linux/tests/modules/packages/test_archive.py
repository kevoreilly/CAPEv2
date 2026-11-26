import os
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
        # Relocatable Python builds (e.g. uv python-build-standalone) resolve stdlib
        # relative to argv[0] unless PYTHONHOME points at sys.base_prefix.
        child_env = {**os.environ, "PYTHONHOME": sys.base_prefix} if kind == "elf" else None
        child = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env)
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


def test_archive_stdlib_zip_tar_and_gzip_fallbacks_without_7z(monkeypatch, tmp_path):
    import gzip
    import io
    import tarfile
    from zipfile import ZipFile

    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setenv("TEMP", str(tmp_path))
    upload = Mock()
    monkeypatch.setattr(archive, "upload_extracted_files", upload)

    # 1. ZIP fallback + zip-slip rejection
    zip_path = tmp_path / "sample.zip"
    with ZipFile(zip_path, "w") as zf:
        zf.writestr("run.sh", "echo ok\n")
        zf.writestr("../escape.sh", "echo bad\n")

    pkg = archive.Archive(options={})
    pkg.get_path_app_in_path = Mock(side_effect=archive.CuckooPackageError("not installed"))
    pkg.execute = Mock(return_value=6001)
    try:
        assert pkg.start(str(zip_path)) == [6001]
        assert upload.call_args.args[1] == ["run.sh"]
        assert not (tmp_path / "escape.sh").exists()
    finally:
        pkg.finish()

    # 2. TAR.GZ fallback + tar-slip rejection
    tar_path = tmp_path / "sample.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        info = tarfile.TarInfo("run.sh")
        data = b"echo tar\n"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        bad = tarfile.TarInfo("../tar_escape.sh")
        bad.size = len(data)
        tf.addfile(bad, io.BytesIO(data))

    pkg_tar = archive.Archive(options={})
    pkg_tar.get_path_app_in_path = Mock(side_effect=archive.CuckooPackageError("not installed"))
    pkg_tar.execute = Mock(return_value=6002)
    try:
        assert pkg_tar.start(str(tar_path)) == [6002]
        assert upload.call_args.args[1] == ["run.sh"]
        assert not (tmp_path / "tar_escape.sh").exists()
    finally:
        pkg_tar.finish()

    # 3. Single-file gzip stream fallback
    gz_path = tmp_path / "drop.sh.gz"
    with gzip.open(gz_path, "wb") as gf:
        gf.write(b"echo gz\n")

    pkg_gz = archive.Archive(options={})
    pkg_gz.get_path_app_in_path = Mock(side_effect=archive.CuckooPackageError("not installed"))
    pkg_gz.execute = Mock(return_value=6003)
    try:
        assert pkg_gz.start(str(gz_path)) == [6003]
        assert upload.call_args.args[1] == ["drop.sh"]
    finally:
        pkg_gz.finish()


def test_archive_explicit_extractor_disables_fallback(monkeypatch, tmp_path):
    from zipfile import ZipFile

    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setattr(archive, "upload_extracted_files", Mock())

    zip_path = tmp_path / "sample.zip"
    with ZipFile(zip_path, "w") as zf:
        zf.writestr("run.sh", "echo ok\n")

    pkg = archive.Archive(options={"extractor": "7z"})
    pkg.get_path_app_in_path = Mock(side_effect=archive.CuckooPackageError("not installed"))
    with pytest.raises(archive.CuckooPackageError, match="7z"):
        pkg.start(str(zip_path))

    pkg_bad = archive.Archive(options={"extractor": "unknown"})
    with pytest.raises(archive.CuckooPackageError, match="Unsupported extractor"):
        pkg_bad.start(str(zip_path))


def test_archive_recursion_without_file_util_and_single_member_unwrap(monkeypatch, tmp_path):
    import io
    from zipfile import ZipFile

    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setenv("TEMP", str(tmp_path))
    upload = Mock()
    monkeypatch.setattr(archive, "upload_extracted_files", upload)

    inner = io.BytesIO()
    with ZipFile(inner, "w") as zf:
        zf.writestr("deep.sh", "echo deep\n")

    jar_buf = io.BytesIO()
    with ZipFile(jar_buf, "w") as jf:
        jf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

    outer = tmp_path / "outer.zip"
    with ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
        zf.writestr("app.jar", jar_buf.getvalue())

    pkg = archive.Archive(options={"recursion_depth": 1})
    pkg.get_path_app_in_path = Mock(side_effect=archive.CuckooPackageError("missing"))
    pkg.execute = Mock(return_value=7001)
    try:
        assert pkg.start(str(outer)) == [7001, 7001]
        uploaded = upload.call_args.args[1]
        assert any(name.endswith("deep.sh") for name in uploaded)
        assert "app.jar" in uploaded
        assert not any("MANIFEST.MF" in name for name in uploaded)
    finally:
        pkg.finish()

    single_wrap = tmp_path / "single.zip"
    with ZipFile(single_wrap, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())

    pkg_default = archive.Archive(options={})
    pkg_default.get_path_app_in_path = Mock(side_effect=archive.CuckooPackageError("missing"))
    pkg_default.execute = Mock(return_value=7002)
    try:
        assert pkg_default.start(str(single_wrap)) == [7002]
        assert any(name.endswith("deep.sh") for name in upload.call_args.args[1])
    finally:
        pkg_default.finish()

    pkg_zero = archive.Archive(options={"recursion_depth": 0})
    pkg_zero.get_path_app_in_path = Mock(side_effect=archive.CuckooPackageError("missing"))
    pkg_zero.execute = Mock(return_value=7003)
    try:
        assert pkg_zero.start(str(single_wrap)) == []
        assert upload.call_args.args[1] == ["inner.zip"]
    finally:
        pkg_zero.finish()


def test_wget_delegates_to_common_archive_package(monkeypatch, tmp_path):
    from zipfile import ZipFile
    from lib.core import packages as core_packages
    from modules.packages import wget

    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setattr(core_packages, "NetlogFile", Mock)
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setattr(archive, "upload_extracted_files", Mock())

    zip_path = tmp_path / "file_malwr"
    with ZipFile(zip_path, "w") as zf:
        zf.writestr("run.sh", "echo wget\n")

    monkeypatch.setattr(wget, "system", lambda _cmd: 0)
    monkeypatch.setattr(wget, "chmod", lambda _p, _m: None)
    monkeypatch.setattr(wget, "_fileinfo", lambda _p: "Zip archive data")

    pkg = wget.Wget("http://example.invalid/a.zip", options={})
    monkeypatch.setattr(
        archive.Archive,
        "get_path_app_in_path",
        lambda self, app: (_ for _ in ()).throw(archive.CuckooPackageError("missing")),
    )
    monkeypatch.setattr(archive.Archive, "execute", lambda self, cmd: 8123)

    orig_prepare = pkg.prepare

    def patched_prepare():
        orig_prepare()
        pkg.target = str(zip_path)

    pkg.prepare = patched_prepare
    try:
        assert pkg.start() == [8123]
        assert isinstance(pkg.real_package, archive.Archive)
    finally:
        pkg.finish()
        assert not Path(pkg.real_package._extraction_dir.name).exists()


def test_archive_file_option_resolves_nested_and_extensionless_tar(monkeypatch, tmp_path):
    import gzip
    import io
    import tarfile
    from zipfile import ZipFile

    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setattr(archive, "upload_extracted_files", Mock())

    assert "arguments" in archive.Archive.option_names

    # 1. Single-member nested ZIP with file= targeting inner member
    inner = io.BytesIO()
    with ZipFile(inner, "w") as zf:
        zf.writestr("sub/run.sh", "echo nested\n")

    outer = tmp_path / "outer.zip"
    with ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())

    pkg = archive.Archive(options={"file": "sub/run.sh"})
    pkg.get_path_app_in_path = Mock(side_effect=archive.CuckooPackageError("missing"))
    cmds = []
    pkg.execute = lambda cmd: cmds.append(cmd) or 9101
    try:
        assert pkg.start(str(outer)) == [9101]
        assert len(cmds) == 1
        assert "sub/run.sh" in cmds[0]
    finally:
        pkg.finish()

    # 2. Extensionless tar extracted by 7z from a .gz archive is unwrapped via magic
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        info = tarfile.TarInfo("drop.sh")
        data = b"echo tar\n"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    gz_path = tmp_path / "archive.gz"
    with gzip.open(gz_path, "wb") as gf:
        gf.write(tar_buf.getvalue())

    def fake_7z(_bin, src, dest, _pw, _multi):
        if src == str(gz_path):
            (Path(dest) / "archive").write_bytes(tar_buf.getvalue())
        else:
            (Path(dest) / "drop.sh").write_bytes(b"echo tar\n")

    monkeypatch.setattr(archive, "extract_archive", fake_7z)
    pkg_gz = archive.Archive(options={"file": "drop.sh"})
    pkg_gz.get_path_app_in_path = Mock(side_effect=lambda name: "/usr/bin/7z" if name == "7z" else (_ for _ in ()).throw(archive.CuckooPackageError("missing")))
    cmds_gz = []
    pkg_gz.execute = lambda cmd: cmds_gz.append(cmd) or 9102
    try:
        assert pkg_gz.start(str(gz_path)) == [9102]
        assert len(cmds_gz) == 1
        assert "drop.sh" in cmds_gz[0]
    finally:
        pkg_gz.finish()


def test_linux_zip_utils_unrar_wrong_password_and_zip_edge_cases(monkeypatch, tmp_path):
    from zipfile import ZipFile
    from lib.common import zip_utils

    # 1. unrar_extractor checks wrong password BEFORE partial entries and appends trailing slash
    out_dir = tmp_path / "unrar_out"
    seen_cmds = []

    def fake_run(cmd, **kwargs):
        seen_cmds.append(cmd)
        if "-pbad" in cmd:
            (out_dir / "partial_dir").mkdir(exist_ok=True)
            return Mock(returncode=11, stdout=b"", stderr=b"Wrong password")
        (out_dir / "run.sh").write_text("echo ok\n")
        return Mock(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(zip_utils.subprocess, "run", fake_run)
    entries = zip_utils.unrar_extractor(
        "/usr/bin/unrar", str(out_dir), str(tmp_path / "enc.rar"), "bad:good", try_multiple_passwords=True
    )
    assert seen_cmds[0][-1].endswith(os.sep)
    assert "run.sh" in entries
    assert not (out_dir / "partial_dir").exists()

    fail_dir = tmp_path / "unrar_fail"

    def fake_run_fail(cmd, **kwargs):
        (fail_dir / "empty_subdir").mkdir(exist_ok=True)
        return Mock(returncode=11, stdout=b"", stderr=b"")

    monkeypatch.setattr(zip_utils.subprocess, "run", fake_run_fail)
    with pytest.raises(archive.CuckooPackageError, match="Wrong password"):
        zip_utils.unrar_extractor("/usr/bin/unrar", str(fail_dir), str(tmp_path / "enc.rar"), "bad")
    assert list(fail_dir.iterdir()) == []

    # 2. extract_zip does not rename source archive when extracting into a separate directory
    src_dir = tmp_path / "src"
    dest_dir = tmp_path / "dest"
    src_dir.mkdir()
    same_zip = src_dir / "sample.zip"
    with ZipFile(same_zip, "w") as zf:
        zf.writestr("sample.zip", b"inner")

    zip_utils.extract_zip(str(same_zip), str(dest_dir), recursive=False)
    assert same_zip.exists()
    assert not (src_dir / "sample.zip.old").exists()
    assert (dest_dir / "sample.zip").read_bytes() == b"inner"

    # 3. extract_zip wraps OSError on conflicting file/dir entries as CuckooPackageError
    conflict = tmp_path / "conflict.zip"
    with ZipFile(conflict, "w") as zf:
        zf.writestr("a", b"file-a")
        zf.writestr("a/b", b"file-b")
    with pytest.raises(archive.CuckooPackageError, match="Unable to extract Zip file"):
        zip_utils.extract_zip(str(conflict), str(tmp_path / "conflict_out"), recursive=False)

