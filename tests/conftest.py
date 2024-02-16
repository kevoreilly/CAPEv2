import pathlib

import pytest

import lib.cuckoo.common.config
import lib.cuckoo.core.database
from lib.cuckoo.common.config import ConfigMeta


@pytest.fixture
def tmp_cuckoo_root(monkeypatch, tmp_path):
    monkeypatch.setattr(lib.cuckoo.core.database, "CUCKOO_ROOT", str(tmp_path))
    yield tmp_path


@pytest.fixture(autouse=True)
def custom_conf_path(request, monkeypatch, tmp_cuckoo_root):
    ConfigMeta.reset()
    monkeypatch.setenv("CAPE_DISABLE_ROOT_CONFIGS", "1")
    path: pathlib.Path = tmp_cuckoo_root / "custom" / "conf"
    path.mkdir(mode=0o755, parents=True)
    monkeypatch.setattr(lib.cuckoo.common.config, "CUSTOM_CONF_DIR", str(path))
    yield path
