from tempfile import NamedTemporaryFile
from unittest.mock import ANY, MagicMock

from lib.cuckoo.common.objects import File
from modules.processing.CAPE import CAPE


class TestConfigUpdates:
    def test_update_no_config(self):
        cape_proc_module = CAPE()
        cape_proc_module.update_cape_configs("Family", None, MagicMock())
        assert cape_proc_module.cape["configs"] == []

    def test_update_empty_config(self):
        cape_proc_module = CAPE()
        cape_proc_module.update_cape_configs("Family", {}, MagicMock())
        assert cape_proc_module.cape["configs"] == []

    def test_update_single_config(self):
        cape_proc_module = CAPE()
        cfg = {"Family": {"SomeKey": "SomeValue"}}
        cape_proc_module.update_cape_configs("Family", cfg, MagicMock())
        expected_cfgs = [cfg]
        assert cape_proc_module.cape["configs"] == expected_cfgs

    def test_update_multiple_configs(self):
        cape_proc_module = CAPE()
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"AnotherKey": "AnotherValue"}}
        cape_proc_module.update_cape_configs("Family", cfg1, MagicMock())
        cape_proc_module.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfgs = [{"Family": {"AnotherKey": "AnotherValue", "SomeKey": "SomeValue"}, "associated_config_hashes": ANY}]
        assert cape_proc_module.cape["configs"] == expected_cfgs

    def test_update_different_families(self):
        cape_proc_module = CAPE()
        cfg1 = {"Family1": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family2": {"SomeKey": "SomeValue"}}
        cape_proc_module.update_cape_configs("Family", cfg1, MagicMock())
        cape_proc_module.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfgs = [
            {"Family1": {"SomeKey": "SomeValue"}, "associated_config_hashes": ANY},
            {"Family2": {"SomeKey": "SomeValue"}, "associated_config_hashes": ANY},
        ]
        assert cape_proc_module.cape["configs"] == expected_cfgs

    def test_update_same_family_overwrites(self):
        # see https://github.com/kevoreilly/CAPEv2/pull/1357
        cape_proc_module = CAPE()
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"SomeKey": "DifferentValue"}}
        cape_proc_module.update_cape_configs("Family", cfg1, MagicMock())
        cape_proc_module.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfg = [
            {"Family": {"SomeKey": "DifferentValue"}, "associated_config_hashes": ANY},
        ]
        assert cape_proc_module.cape["configs"] == expected_cfg

    def test_update_config_file_obj(self):
        cape_proc_module = CAPE()
        with NamedTemporaryFile(mode="wb") as f:
            f.write(b"fake file for configs")
            file_obj = File(f.name).calc_hashes()
            cfg = {"Family": {"SomeKey": "SomeValue"}}
            cape_proc_module.update_cape_configs("Family", cfg, file_obj)
        actual_cfg = cape_proc_module.cape["configs"]
        assert "Family" in actual_cfg[0]
        assert "associated_config_hashes" in actual_cfg[0]
        hashes = actual_cfg[0]["associated_config_hashes"]
        assert hashes["md5"].startswith("d41")
        assert hashes["sha1"].startswith("da3")
        assert hashes["sha256"].startswith("e3b")
        assert hashes["sha512"].startswith("cf8")
        assert hashes["sha3_384"].startswith("0c6")
