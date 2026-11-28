from types import SimpleNamespace

import pytest

from lib.cuckoo.common.integrations import floss as floss_mod

PE = b"MZ" + b"\x00" * 62
ELF = b"\x7fELF" + b"\x00" * 60
DATA = b"\x90" * 64


def _fake_floss_311():
    # FLOSS <= 3.1.x: boolean check, PE only.
    return SimpleNamespace(is_supported_file_type=lambda path: path.read_bytes()[:2] == b"MZ")


def _fake_floss_320():
    # FLOSS 3.2.0 replaced is_supported_file_type() with get_file_type(), which returns
    # the file magic, or a truthy marker for unsupported files.
    def get_file_type(path):
        magic = path.read_bytes()[:4]
        if magic == b"\x7fELF":
            return b"\x7fELF"
        if magic[:2] == b"MZ":
            return b"MZ"
        return b"unsupported"

    return SimpleNamespace(get_file_type=get_file_type, SUPPORTED_FILE_MAGIC_PE=b"MZ")


FLOSS_APIS = pytest.mark.parametrize("make_fm", [_fake_floss_311, _fake_floss_320], ids=["floss311", "floss320"])


def _install_fm(monkeypatch, fm):
    """Install a fake floss.main whose analysis pipeline stops right after load_vw()."""
    loaded_formats = []

    def load_vw(sample_path, fileformat, sigpaths, should_save_workspace=False):
        loaded_formats.append(fileformat)
        return object()

    def select_functions(vw, asked_functions):
        raise ValueError("stop after load_vw")

    fm.set_log_config = lambda debug, quiet: None
    fm.DebugLevel = SimpleNamespace(NONE=0, DEFAULT=1)
    fm.get_signatures = lambda sigs_path: []
    fm.load_vw = load_vw
    fm.select_functions = select_functions
    monkeypatch.setattr(floss_mod, "HAVE_FLOSS", True)
    monkeypatch.setattr(floss_mod, "fm", fm, raising=False)
    return loaded_formats


def _run_worker(path, package):
    return floss_mod._run_floss_analysis(str(path), package, 5, False, True, True, True, "data/flare-signatures")


@FLOSS_APIS
@pytest.mark.parametrize(
    ("content", "package", "expected"),
    [
        (PE, "exe", True),
        (DATA, "exe", False),
        (ELF, "exe", False),
        (DATA, "shellcode", True),
        (DATA, "shellcode_x64", True),
    ],
    ids=["pe", "unsupported", "elf", "shellcode", "shellcode_x64"],
)
def test_floss_parent_file_type_check(monkeypatch, tmp_path, make_fm, content, package, expected):
    _install_fm(monkeypatch, make_fm())
    sample = tmp_path / "sample"
    sample.write_bytes(content)

    assert floss_mod._is_supported_floss_input(str(sample), package) is expected


@FLOSS_APIS
@pytest.mark.parametrize(
    ("content", "package", "expected_format"),
    [
        (PE, "exe", "pe"),
        (PE, "shellcode", "pe"),
        (DATA, "shellcode", "sc32"),
        (DATA, "shellcode_x64", "sc64"),
        (DATA, "exe", None),
        (ELF, "exe", None),
    ],
    ids=["pe", "pe_shellcode_package", "shellcode", "shellcode_x64", "unsupported", "elf"],
)
def test_floss_worker_selects_load_format(monkeypatch, tmp_path, make_fm, content, package, expected_format):
    loaded_formats = _install_fm(monkeypatch, make_fm())
    sample = tmp_path / "sample"
    sample.write_bytes(content)

    assert _run_worker(sample, package) == {}
    assert loaded_formats == ([expected_format] if expected_format else [])
