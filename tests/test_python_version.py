import sys

import pytest

import lib.cuckoo


def test_get_min_python_version_from_repo_pyproject(monkeypatch):
    monkeypatch.delenv("CAPE_MIN_PYTHON", raising=False)
    assert lib.cuckoo.get_min_python_version() == (3, 14)


def test_get_min_python_version_parses_custom_pyproject_and_ignores_comments(monkeypatch, tmp_path):
    monkeypatch.delenv("CAPE_MIN_PYTHON", raising=False)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "# requires-python = \">=3.8\"\n[project]\nrequires-python = '>=3.15, <4.0'\n",
        encoding="utf-8",
    )
    assert lib.cuckoo.get_min_python_version(str(pyproject)) == (3, 15)


def test_get_min_python_version_falls_back_when_pyproject_missing_or_unbounded(monkeypatch, tmp_path):
    monkeypatch.delenv("CAPE_MIN_PYTHON", raising=False)
    assert lib.cuckoo.get_min_python_version(str(tmp_path / "missing.toml")) == lib.cuckoo._FALLBACK_MIN_PYTHON

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "CAPEv2"\n', encoding="utf-8")
    assert lib.cuckoo.get_min_python_version(str(pyproject)) == lib.cuckoo._FALLBACK_MIN_PYTHON


def test_get_min_python_version_env_override(monkeypatch, tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nrequires-python = ">=3.14, <4.0"\n', encoding="utf-8")

    monkeypatch.setenv("CAPE_MIN_PYTHON", "3.12")
    assert lib.cuckoo.get_min_python_version(str(pyproject)) == (3, 12)

    monkeypatch.setenv("CAPE_MIN_PYTHON", "3.15.2")
    assert lib.cuckoo.get_min_python_version(str(pyproject)) == (3, 15)

    monkeypatch.setenv("CAPE_MIN_PYTHON", "invalid")
    assert lib.cuckoo.get_min_python_version(str(pyproject)) == (3, 14)


def test_check_python_version_exits_when_too_old(monkeypatch):
    monkeypatch.delenv("CAPE_SKIP_PYTHON_VERSION_CHECK", raising=False)
    monkeypatch.setenv("CAPE_MIN_PYTHON", "3.14")
    monkeypatch.setattr(sys, "version_info", (3, 10, 0, "final", 0))

    with pytest.raises(SystemExit, match=r"please use >= 3\.14"):
        lib.cuckoo.check_python_version()


def test_check_python_version_allows_supported_or_skipped(monkeypatch):
    monkeypatch.delenv("CAPE_SKIP_PYTHON_VERSION_CHECK", raising=False)
    monkeypatch.setenv("CAPE_MIN_PYTHON", "3.14")
    monkeypatch.setattr(sys, "version_info", (3, 14, 0, "final", 0))
    lib.cuckoo.check_python_version()

    monkeypatch.setenv("CAPE_SKIP_PYTHON_VERSION_CHECK", "1")
    monkeypatch.setattr(sys, "version_info", (3, 10, 0, "final", 0))
    lib.cuckoo.check_python_version()
