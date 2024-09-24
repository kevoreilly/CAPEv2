import os
import pathlib
import tempfile

import pytest

import lib.cuckoo.common.config
import lib.cuckoo.core.analysis_manager
import lib.cuckoo.core.database
from lib.cuckoo.common.config import ConfigMeta
from lib.cuckoo.core.database import Database, init_database, reset_database_FOR_TESTING_ONLY


@pytest.fixture
def db():
    reset_database_FOR_TESTING_ONLY()
    try:
        init_database(dsn="sqlite://")
        retval = Database()
        retval.engine.echo = True
        yield retval
    finally:
        reset_database_FOR_TESTING_ONLY()


@pytest.fixture
def tmp_cuckoo_root(monkeypatch, tmp_path):
    monkeypatch.setattr(lib.cuckoo.core.database, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(lib.cuckoo.core.analysis_manager, "CUCKOO_ROOT", str(tmp_path))
    yield tmp_path


@pytest.fixture(autouse=True)
def custom_conf_path(request, monkeypatch, tmp_cuckoo_root):
    monkeypatch.setenv("CAPE_DISABLE_ROOT_CONFIGS", "1")
    path: pathlib.Path = tmp_cuckoo_root / "custom" / "conf"
    path.mkdir(mode=0o755, parents=True)
    monkeypatch.setattr(lib.cuckoo.common.config, "CUSTOM_CONF_DIR", str(path))
    ConfigMeta.refresh()
    yield path


@pytest.fixture
def temp_pe32(tmp_path):
    """Writes a temporary file that libmagic identifies as:
    'MS-DOS executable PE32 executable Intel 80386, for MS Windows'
    """
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=tmp_path) as f:
        pe_header = b"\x4d\x5a\x00\x00\x50\x45\x00\x00\x4c\x01\x01\x00\x6a\x2a\x58\xc3\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x03\x01\x0b\x01\x08\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x40\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x68\x00\x00\x00\x64\x00\x00\x00\x00\x00\x00\x00\x02"
        f.write(pe_header)
    yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_pe64(tmp_path):
    """Writes a temporary file that libmagic identifies as:
    'MS-DOS executable PE32+ executable x86-64, for MS Windows'
    """
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=tmp_path) as f:
        pe_header = b"\x4d\x5a\x00\x00\x50\x45\x00\x00\x64\x86\x01\x00\x6a\x2a\x58\xc3\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x03\x01\x0b\x01\x08\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x40\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x68\x00\x00\x00\x64\x00\x00\x00\x00\x00\x00\x00\x02"
        f.write(pe_header)
    yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_pe_aarch64(tmp_path):
    """Writes a temporary file that libmagic identifies as:
    'MS-DOS executable PE32+ executable Aarch64, for MS Windows'
    """
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=tmp_path) as f:
        pe_header = b"\x4d\x5a\x00\x00\x50\x45\x00\x00\x64\xaa\x01\x00\x6a\x2a\x58\xc3\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x03\x01\x0b\x01\x08\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x40\x00\x04\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x68\x00\x00\x00\x64\x00\x00\x00\x00\x00\x00\x00\x02"
        f.write(pe_header)
    yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_elf32(tmp_path):
    """Writes a temporary file that libmagic identifies as:
    'ELF 32-bit LSB'
    """
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=tmp_path) as f:
        f.write(b"\x7f\x45\x4c\x46\x01\x01\x01")
    yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_elf64(tmp_path):
    """Writes a temporary file that libmagic identifies as:
    'ELF 64-bit LSB'
    """
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=tmp_path) as f:
        f.write(b"\x7f\x45\x4c\x46\x02\x01\x01")
    yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_macho_arm64(tmp_path):
    """Writes a temporary file that libmagic identifies as:
    'Mach-O 64-bit arm64 executable'
    """
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=tmp_path) as f:
        f.write(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00")
    yield f.name
    os.unlink(f.name)
