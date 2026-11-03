import shlex
import shutil
import stat
import subprocess
import sys
from unittest.mock import Mock

import pytest

from lib.common import abstracts
from lib.common.exceptions import CuckooPackageError


@pytest.fixture
def package(monkeypatch):
    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    return abstracts.Package(options={})


@pytest.mark.skipif(sys.platform != "linux", reason="Requires an ELF Python interpreter")
def test_extracted_elf_gets_owner_execute_and_literal_path(package, tmp_path):
    target = tmp_path / 'payload "quoted" $(printf injected).bin'
    shutil.copyfile(sys.executable, target)
    target.chmod(0o640)
    package.options["arguments"] = '-c ' + shlex.quote("print('two words')")
    outputs = []

    def execute(command):
        child = subprocess.run(command, shell=True, capture_output=True, timeout=5)
        assert child.returncode == 0, child.stderr
        outputs.append(child.stdout)
        return 4242

    package.execute = execute
    assert package.execute_interesting_file(str(tmp_path), target.name, str(target)) == 4242
    assert outputs == [b"two words\n"]
    assert stat.S_IMODE(target.stat().st_mode) == 0o740


@pytest.mark.skipif(sys.platform != "linux", reason="Requires an ELF Python interpreter")
def test_extracted_elf_rejects_external_symlink_before_chmod(package, tmp_path):
    root = tmp_path / "extracted"
    root.mkdir()
    outside = tmp_path / "outside"
    shutil.copyfile(sys.executable, outside)
    outside.chmod(0o640)
    target = root / "payload"
    target.symlink_to(outside)
    package.execute = Mock()
    with pytest.raises(CuckooPackageError, match="outside the extraction directory"):
        package.execute_interesting_file(str(root), target.name, str(target))
    assert stat.S_IMODE(outside.stat().st_mode) == 0o640
    package.execute.assert_not_called()


@pytest.mark.parametrize("suffix, interpreter, contents", [
    (".sh", "/usr/bin/bash", "printf 'literal-ok\\n'"),
    (".py", "/usr/bin/python3", "print('literal-ok')"),
    (".pl", "/usr/bin/perl", 'print "literal-ok\\n";'),
])
def test_interpreted_member_paths_are_shell_literals(package, tmp_path, suffix, interpreter, contents):
    if not shutil.which(interpreter):
        pytest.skip(f"{interpreter} is required")
    target = tmp_path / ('payload "quoted" $(printf injected) `printf changed`' + suffix)
    target.write_text(contents)
    outputs = []

    def execute(command):
        child = subprocess.run(command, shell=True, capture_output=True, timeout=5)
        assert child.returncode == 0, child.stderr
        outputs.append(child.stdout)
        return 4242

    package.execute = execute
    assert package.execute_interesting_file(str(tmp_path), target.name, str(target)) == 4242
    assert outputs == [b"literal-ok\n"]


def test_interpreted_script_rejects_external_symlink(package, tmp_path):
    root = tmp_path / "extracted"
    root.mkdir()
    outside = tmp_path / "outside.sh"
    outside.write_text("printf 'outside\n'")
    target = root / "payload.sh"
    target.symlink_to(outside)
    package.execute = Mock()
    with pytest.raises(CuckooPackageError, match="outside the extraction directory"):
        package.execute_interesting_file(str(root), target.name, str(target))
    package.execute.assert_not_called()


def test_missing_target_file_returns_none(package, tmp_path):
    package.execute = Mock()
    assert package.execute_interesting_file(str(tmp_path), "missing.sh", str(tmp_path / "missing.sh")) is None
    package.execute.assert_not_called()
