from modules.processing.CAPE import CAPE


class TestConfigUpdates:
    def test_update_no_config(self):
        cape_proc_module = CAPE()
        cape_proc_module.update_cape_configs("Family", None)
        assert cape_proc_module.cape["configs"] == []

    def test_update_empty_config(self):
        cape_proc_module = CAPE()
        cape_proc_module.update_cape_configs("Family", {})
        assert cape_proc_module.cape["configs"] == []

    def test_update_single_config(self):
        cape_proc_module = CAPE()
        cfg = {"Family": {"SomeKey": "SomeValue"}}
        cape_proc_module.update_cape_configs("Family", cfg)
        expected_cfgs = [cfg]
        assert cape_proc_module.cape["configs"] == expected_cfgs

    def test_update_multiple_configs(self):
        cape_proc_module = CAPE()
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"AnotherKey": "AnotherValue"}}
        cape_proc_module.update_cape_configs("Family", cfg1)
        cape_proc_module.update_cape_configs("Family", cfg2)
        expected_cfgs = [{"Family": {"AnotherKey": "AnotherValue", "SomeKey": "SomeValue"}}]
        assert cape_proc_module.cape["configs"] == expected_cfgs

    def test_update_different_families(self):
        cape_proc_module = CAPE()
        cfg1 = {"Family1": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family2": {"SomeKey": "SomeValue"}}
        cape_proc_module.update_cape_configs("Family", cfg1)
        cape_proc_module.update_cape_configs("Family", cfg2)
        expected_cfgs = [{"Family1": {"SomeKey": "SomeValue"}}, {"Family2": {"SomeKey": "SomeValue"}}]
        assert cape_proc_module.cape["configs"] == expected_cfgs

    def test_update_same_family_overwrites(self):
        # see https://github.com/kevoreilly/CAPEv2/pull/1357
        cape_proc_module = CAPE()
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"SomeKey": "DifferentValue"}}
        cape_proc_module.update_cape_configs("Family", cfg1)
        cape_proc_module.update_cape_configs("Family", cfg2)
        expected_cfg = [{"Family": {"SomeKey": "DifferentValue"}}]
        assert cape_proc_module.cape["configs"] == expected_cfg
