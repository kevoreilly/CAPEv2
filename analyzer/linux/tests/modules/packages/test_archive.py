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
    monkeypatch.setattr(archive, "get_file_names", lambda *args: ["run.sh"])
    # Keep the legacy root layout inside the test directory.
    join = archive.os.path.join
    monkeypatch.setattr(archive.os.path, "join", lambda *parts: join(str(tmp_path), *parts[1:]) if parts[0] == "/" else join(*parts))
    monkeypatch.setattr(archive.shutil, "copy", Mock())
    monkeypatch.setattr(archive.shutil, "copytree", Mock())

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
