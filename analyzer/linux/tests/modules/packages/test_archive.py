import stat
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from lib.common import abstracts
from modules.packages import archive


@pytest.fixture
def prepare_archive(monkeypatch, tmp_path):
    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setattr(archive, "get_file_names", lambda *args: ["run.sh"])

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
