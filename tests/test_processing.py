from tempfile import NamedTemporaryFile
from unittest.mock import ANY, MagicMock, patch

import pytest

from lib.cuckoo.common.objects import File
from modules.processing.CAPE import CAPE
from modules.processing.deduplication import reindex_screenshots


@pytest.fixture
def cape_processor():
    retval = CAPE()
    retval._set_dict_keys()
    yield retval


class TestConfigUpdates:
    def test_update_no_config(self, cape_processor):
        cape_processor.update_cape_configs("Family", None, MagicMock())
        assert cape_processor.cape["configs"] == []

    def test_update_empty_config(self, cape_processor):
        cape_processor.update_cape_configs("Family", {}, MagicMock())
        assert cape_processor.cape["configs"] == []

    def test_update_single_config(self, cape_processor):
        cfg = {"Family": {"SomeKey": "SomeValue"}}
        cape_processor.update_cape_configs("Family", cfg, MagicMock())
        expected_cfgs = [cfg]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_multiple_configs(self, cape_processor):
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"AnotherKey": "AnotherValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfgs = [{"Family": {"AnotherKey": "AnotherValue", "SomeKey": "SomeValue"}, "_associated_config_hashes": ANY}]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_different_families(self, cape_processor):
        cfg1 = {"Family1": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family2": {"SomeKey": "SomeValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfgs = [
            {"Family1": {"SomeKey": "SomeValue"}, "_associated_config_hashes": ANY},
            {"Family2": {"SomeKey": "SomeValue"}, "_associated_config_hashes": ANY},
        ]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_same_family_overwrites(self, cape_processor):
        # see https://github.com/kevoreilly/CAPEv2/pull/1357
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfg = [
            {"Family": {"SomeKey": "DifferentValue"}, "_associated_config_hashes": ANY},
        ]
        assert cape_processor.cape["configs"] == expected_cfg

    def test_update_config_file_obj(self, cape_processor):
        with NamedTemporaryFile(mode="wb") as f:
            f.write(b"fake file for configs")
            file_obj = File(f.name).get_all_hashes()
            cfg = {"Family": {"SomeKey": "SomeValue"}}
            cape_processor.update_cape_configs("Family", cfg, file_obj)
        actual_cfg = cape_processor.cape["configs"]
        assert "Family" in actual_cfg[0]
        assert "_associated_config_hashes" in actual_cfg[0]
        hashes = actual_cfg[0]["_associated_config_hashes"]
        assert len(hashes) == 1
        assert hashes[0]["md5"].startswith("d41")
        assert hashes[0]["sha1"].startswith("da3")
        assert hashes[0]["sha256"].startswith("e3b")
        assert hashes[0]["sha512"].startswith("cf8")
        assert hashes[0]["sha3_384"].startswith("0c6")


class TestAnalysisConfigLinks:
    @pytest.mark.parametrize("category", ["static", "file"])
    def test_analysis_linkability(self, category, cape_processor):
        cape_processor.results = {"target": {"category": category}}
        hashes = {
            "md5": "fake-md5",
            "sha1": "fake-sha1",
            "sha256": "fake-sha256",
            "sha512": "fake-sha512",
            "sha3_384": "fake-sha3_384",
        }
        cape_processor.results["target"]["file"] = hashes
        cfg = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.cape["configs"] = [cfg]
        cape_processor.link_configs_to_analysis()
        assert "_associated_analysis_hashes" in cfg
        assert cfg["_associated_analysis_hashes"] == hashes

    @pytest.mark.parametrize("category", ["resubmit", "sample", "pcap", "url", "dlnexec", "vtdl"])
    def test_static_links(self, category, cape_processor):
        cape_processor.results = {"target": {"category": category}}
        cfg = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.cape["configs"] = [cfg]
        cape_processor.link_configs_to_analysis()
        assert "_associated_analysis_hashes" not in cfg


class TestDeduplication:
    @patch("os.rename")
    @patch("os.listdir")
    def test_reindex(self, os_listdir, os_rename):
        dirlist = ["foo.jpg", "bar.jpg", "baz.jpg"]
        os_listdir.return_value = dirlist
        reindex_screenshots("shots")
        assert os_rename.call_count == 3
        os_rename.assert_any_call("shots/bar.jpg", "shots/0000.jpg")
        os_rename.assert_any_call("shots/baz.jpg", "shots/0001.jpg")
        os_rename.assert_any_call("shots/foo.jpg", "shots/0002.jpg")
