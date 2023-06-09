import pytest

import lib.cuckoo.core.database


@pytest.fixture
def tmp_cuckoo_root(monkeypatch, tmp_path):
    monkeypatch.setattr(lib.cuckoo.core.database, "CUCKOO_ROOT", str(tmp_path))
