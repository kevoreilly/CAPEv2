# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import, print_function
import textwrap

import pytest

import lib.cuckoo.common.config
from lib.cuckoo.common.config import NOT_SET, AnalysisConfig, Config, ConfigMeta
from lib.cuckoo.common.exceptions import CuckooConfigNotInitializedError, CuckooOperationalError


@pytest.fixture
def analysis_config(tmp_path):
    CONF_EXAMPLE = """
[cuckoo]
debug = off
analysis_timeout = 120
critical_timeout = 600
delete_original = off
machine_manager = kvm
use_sniffer = no
tcpdump = /usr/sbin/tcpdump
interface = vboxnet0
"""
    path = tmp_path / "analysis.conf"
    with open(path, mode="w") as fil:
        fil.write(CONF_EXAMPLE)
    yield AnalysisConfig(path)


@pytest.fixture(autouse=True)
def reset():
    ConfigMeta.reset()
    Config.config_dirs = NOT_SET


class TestAnalysisConfig:
    def test_get_option_exist(self, analysis_config):
        """Fetch an option of each type from default config file."""
        assert analysis_config.get("cuckoo")["debug"] is False
        assert analysis_config.get("cuckoo")["tcpdump"] == "/usr/sbin/tcpdump"
        assert analysis_config.get("cuckoo")["critical_timeout"] == 600

    def test_dotted_syntax(self, analysis_config):
        assert analysis_config.cuckoo.delete_original is False

    def test_config_file_not_found(self):
        assert AnalysisConfig("foo")

    def test_get_option_not_found(self, analysis_config):
        with pytest.raises(CuckooOperationalError):
            analysis_config.get("foo")

    def test_get_option_not_found_in_file_not_found(self):
        analysis_config = AnalysisConfig("bar")
        with pytest.raises(CuckooOperationalError):
            analysis_config.get("foo")

    def test_analysis_configs_are_not_reused(self, tmp_path, analysis_config):
        analysis_config2 = AnalysisConfig(str(tmp_path / "analysis.conf"))
        assert analysis_config is not analysis_config2


def write_config(path, content):
    with open(path, mode="w") as fil:
        fil.write(textwrap.dedent(content))


@pytest.fixture
def default_config(monkeypatch, tmp_path):
    default_dir = tmp_path / "default"
    default_dir.mkdir()
    default_conf = default_dir / "conf" / "cuckoo.conf"
    default_conf.parent.mkdir()
    write_config(
        default_conf,
        """
        [cuckoo]
        debug = false
        analysis_timeout = 120
        """,
    )
    monkeypatch.setattr(lib.cuckoo.common.config, "CUCKOO_ROOT", str(default_dir))
    yield default_conf


class TestConfig:
    def test_option_override(self, tmp_path, default_config):
        """Fetch an option of each type from default config file."""
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        custom_conf = custom_dir / "cuckoo.conf"
        write_config(
            custom_conf,
            """
            [cuckoo]
            debug = true
            """,
        )

        Config.initialize((str(custom_dir),))
        config = Config("cuckoo")

        # This was overridden in the custom config.
        assert config.get("cuckoo")["debug"] is True
        # This was inherited from the default config.
        assert config.get("cuckoo")["analysis_timeout"] == 120

    def test_cannot_create_config_before_initialized(self, default_config):
        with pytest.raises(CuckooConfigNotInitializedError):
            Config("cuckoo")

    def test_nonexistent_custom_file(self, tmp_path, default_config):
        """Verify that there are no problems when the file to be processed does not
        exist in the custom config dir.
        """
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        Config.initialize((str(custom_dir),))
        config = Config("cuckoo")
        assert config.get("cuckoo")["debug"] is False
        assert config.get("cuckoo")["analysis_timeout"] == 120

    def test_singleton_configs(self, default_config):
        """Verify that Config objects that were passed the same "file_name" argument
        are reused.
        """
        Config.initialize()
        config1 = Config("cuckoo")
        config2 = Config("cuckoo")
        assert config1 is config2

    def test_initialize_with_nonexistent_dir(self, tmp_path):
        """Verify that an OSError is raised if Config.initialize() is called with a
        directory that does not exist.
        """
        with pytest.raises(OSError):
            Config.initialize((str(tmp_path / "custom"),))

    def test_environment_interpolation(self, tmp_path, monkeypatch):
        """Verify that environment variables are able to be referenced in config
        files.
        """
        default_dir = tmp_path / "default"
        default_dir.mkdir()
        default_conf = default_dir / "conf" / "auxiliary.conf"
        default_conf.parent.mkdir()
        write_config(
            default_conf,
            """
            [virustotaldl]
            enabled = no
            #dlintelkey = SomeKeyWithDLAccess
            dlpath = /tmp/
            """,
        )
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        custom_conf = custom_dir / "auxiliary.conf"
        write_config(
            custom_conf,
            """
            [virustotaldl]
            enabled = yes
            dlintelkey = %(ENV:DLINTELKEY)s
            """,
        )

        custom_secret = "MyReallySecretKeyWithAPercent(%)InIt"
        monkeypatch.setattr(lib.cuckoo.common.config, "CUCKOO_ROOT", str(default_dir))
        monkeypatch.setenv("DLINTELKEY", custom_secret)
        Config.initialize((str(custom_dir),))
        config = Config("auxiliary")
        section = config.get("virustotaldl")
        # Inherited from default config
        assert section.dlpath == "/tmp/"
        # Overridden from custom config
        assert section.enabled is True
        # Overridden from custom config and uses environment variable
        assert section.dlintelkey == custom_secret
