# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest

from lib.cuckoo.common.integrations import magika as magika_integration


class FakeOutput:
    label = "pebin"
    description = "Windows Portable Executable"
    mime_type = "application/vnd.microsoft.portable-executable"
    group = "executable"
    is_text = False
    extensions = ["exe", "dll"]


class FakeResult:
    ok = True
    status = "ok"
    score = 0.9912345
    output = FakeOutput()
    prediction = None


class TestResultNormalisation:
    def test_result_to_dict(self):
        info = magika_integration._result_to_dict(FakeResult())
        assert info["label"] == "pebin"
        assert info["mime_type"] == "application/vnd.microsoft.portable-executable"
        assert info["score"] == 0.9912
        assert info["low_confidence"] is False

    def test_not_ok_result_is_dropped(self):
        class NotOk(FakeResult):
            ok = False
            status = "file_not_found_error"

        assert magika_integration._result_to_dict(NotOk()) == {}

    def test_low_confidence_flagged(self, monkeypatch):
        monkeypatch.setattr(magika_integration, "MAGIKA_MIN_SCORE", 0.99999)
        assert magika_integration._result_to_dict(FakeResult())["low_confidence"] is True


class TestAdditiveOnly:
    """Magika must never rewrite the libmagic verdict."""

    # objects.py does `from ...magika import magika_info`, binding the name
    # into its own namespace, so these must patch the objects module -- not
    # the integration module, which would leave File calling the real one and
    # make the assertion below pass for the wrong reason.
    FAKE = {"label": "pebin", "description": "Windows PE", "mime_type": "application/x-dosexec", "score": 1.0}

    def test_get_type_is_untouched(self, monkeypatch, tmp_path):
        from lib.cuckoo.common import objects

        sample = tmp_path / "hello.txt"
        sample.write_text("plain ascii text, nothing to see here\n")

        monkeypatch.setattr(objects, "MAGIKA_ENABLED", True)
        monkeypatch.setattr(objects, "magika_info", lambda path: dict(TestAdditiveOnly.FAKE))

        f = objects.File(str(sample))
        magic_type = f.get_content_type()
        assert f.get_type() == magic_type
        assert "pebin" not in (f.get_type() or "")
        assert "Magika" not in (f.get_type() or "")

    def test_get_all_carries_magika_beside_type(self, monkeypatch, tmp_path):
        """The additive half: the block is present and `type` is unchanged."""
        from lib.cuckoo.common import objects

        sample = tmp_path / "hello.txt"
        sample.write_text("plain ascii text, nothing to see here\n")

        monkeypatch.setattr(objects, "MAGIKA_ENABLED", True)
        monkeypatch.setattr(objects, "magika_info", lambda path: dict(TestAdditiveOnly.FAKE))

        infos, _ = objects.File(str(sample)).get_all()
        assert infos["magika"]["label"] == "pebin"
        assert "pebin" not in infos["type"]

    def test_get_all_omits_key_when_no_result(self, monkeypatch, tmp_path):
        """No result must mean no key at all, so the UI row does not render."""
        from lib.cuckoo.common import objects

        sample = tmp_path / "hello.txt"
        sample.write_text("plain ascii text, nothing to see here\n")

        monkeypatch.setattr(objects, "MAGIKA_ENABLED", True)
        monkeypatch.setattr(objects, "magika_info", lambda path: {})

        infos, _ = objects.File(str(sample)).get_all()
        assert "magika" not in infos

    def test_module_exposes_no_type_mutators(self):
        # Guard against the mutation helpers being reintroduced.
        for name in ("apply_magika_to_type", "magika_type_string", "is_unknown_magic"):
            assert not hasattr(magika_integration, name)


class TestDisabledPath:
    def test_disabled_returns_empty(self, monkeypatch, tmp_path):
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"MZ" + b"A" * 512)
        monkeypatch.setattr(magika_integration, "MAGIKA_ENABLED", False)
        assert magika_integration.magika_info(str(sample)) == {}

    def test_missing_file_returns_empty(self, monkeypatch):
        monkeypatch.setattr(magika_integration, "MAGIKA_ENABLED", True)
        monkeypatch.setattr(magika_integration, "HAVE_MAGIKA", True)
        assert magika_integration.magika_info("/nonexistent/path/xyz") == {}

    def test_max_file_size_guard(self, monkeypatch, tmp_path):
        sample = tmp_path / "big.bin"
        sample.write_bytes(b"A" * 2048)
        monkeypatch.setattr(magika_integration, "MAGIKA_ENABLED", True)
        monkeypatch.setattr(magika_integration, "HAVE_MAGIKA", True)
        # 2KB file, guard set to effectively 0 bytes worth of MB -> 1MB limit
        monkeypatch.setattr(magika_integration, "MAGIKA_MAX_FILE_SIZE", 0.000001)
        assert magika_integration.magika_info(str(sample)) == {}


class TestLiveIdentification:
    """Only runs where the optional dependency is actually installed."""

    def test_identify_real_file(self, monkeypatch, tmp_path):
        pytest.importorskip("magika")
        monkeypatch.setattr(magika_integration, "MAGIKA_ENABLED", True)
        monkeypatch.setattr(magika_integration, "HAVE_MAGIKA", True)
        if magika_integration._magika_module is None:
            monkeypatch.setattr(magika_integration, "_magika_module", __import__("magika"))
        magika_integration.clear_magika_cache()

        sample = tmp_path / "hello.py"
        sample.write_text("import os\n\n\ndef main():\n    print(os.getcwd())\n")
        info = magika_integration.magika_info(str(sample))
        assert info.get("label") == "python"
        assert info.get("score") is not None

        # second call is served from cache
        assert magika_integration.magika_info(str(sample)) == info
        magika_integration.clear_magika_cache()
