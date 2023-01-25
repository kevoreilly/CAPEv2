# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import configparser
import textwrap

import pytest

import lib.cuckoo.common.config
from lib.cuckoo.common.config import AnalysisConfig, Config, ConfigMeta
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.path_utils import path_write_file


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
    path_write_file(path, CONF_EXAMPLE, mode="text")
    yield AnalysisConfig(path)


@pytest.fixture(autouse=True)
def reset():
    ConfigMeta.reset()


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
    path_write_file(path, textwrap.dedent(content), mode="text")


@pytest.fixture
def custom_conf_dir(monkeypatch, tmp_path):
    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()
    monkeypatch.setattr(lib.cuckoo.common.config, "CUSTOM_CONF_DIR", str(custom_dir))
    yield custom_dir


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
    def test_option_override(self, custom_conf_dir, default_config):
        """Fetch an option of each type from default config file."""
        custom_conf = custom_conf_dir / "cuckoo.conf"
        write_config(
            custom_conf,
            """
            [cuckoo]
            debug = true
            """,
        )
        config = Config("cuckoo")

        # This was overridden in the custom config.
        assert config.get("cuckoo")["debug"] is True
        # This was inherited from the default config.
        assert config.get("cuckoo")["analysis_timeout"] == 120

    def test_nonexistent_custom_file(self, custom_conf_dir, default_config):
        """Verify that there are no problems when the file to be processed does not
        exist in the custom config dir.
        """
        config = Config("cuckoo")
        assert config.get("cuckoo")["debug"] is False
        assert config.get("cuckoo")["analysis_timeout"] == 120

    def test_subdirs(self, custom_conf_dir):
        api_conf = custom_conf_dir / "api.conf"
        write_config(
            api_conf,
            """
            [api]
            ratelimit = no
            """,
        )
        api_conf_d_dir = custom_conf_dir / "api.conf.d"
        api_conf_d_dir.mkdir()
        host_specific_conf = api_conf_d_dir / "01_host_specific.conf"
        url = "https://somehost.example.com"
        write_config(
            host_specific_conf,
            f"""
            [api]
            url = {url}
            """,
        )
        config = Config("api")
        # This is set to 'no' in the default api.conf and not overridden.
        assert config.get("api")["token_auth_enabled"] is False
        # This is set to 'yes' in the default api.conf but overridden in the custom
        # api.conf.
        assert config.get("api")["ratelimit"] is False
        # This is set to http://example.tld in the default api.conf and overridden in
        # api.conf.d/01_host_specific.conf.
        assert config.get("api")["url"] == url

    def test_singleton_configs(self, default_config):
        """Verify that Config objects that were passed the same "file_name" argument
        are reused.
        """
        config1 = Config("cuckoo")
        config2 = Config("cuckoo")
        assert config1 is config2

    def test_environment_interpolation(self, default_config, custom_conf_dir, monkeypatch):
        """Verify that environment variables are able to be referenced in config
        files.
        """
        default_dir = default_config.parent
        aux_conf = default_dir / "auxiliary.conf"
        write_config(
            aux_conf,
            """
            [virustotaldl]
            enabled = no
            #dlintelkey = SomeKeyWithDLAccess
            dlpath = /tmp/
            """,
        )
        custom_conf = custom_conf_dir / "auxiliary.conf"
        write_config(
            custom_conf,
            """
            [virustotaldl]
            enabled = yes
            dlintelkey = %(ENV:DLINTELKEY)s
            """,
        )

        custom_secret = "MyReallySecretKeyWithAPercent(%)InIt"
        monkeypatch.setenv("DLINTELKEY", custom_secret)
        config = Config("auxiliary")
        section = config.get("virustotaldl")
        # Inherited from default config
        assert section.dlpath == "/tmp/"
        # Overridden from custom config
        assert section.enabled is True
        # Overridden from custom config and uses environment variable
        assert section.dlintelkey == custom_secret

    def test_missing_environment_interpolation(self, default_config, custom_conf_dir, monkeypatch):
        """Verify that an exception is raised if an ENV variable is to be used in a
        config file, but that variable is not present in the environment.
        """
        default_dir = default_config.parent
        aux_conf = default_dir / "auxiliary.conf"
        write_config(
            aux_conf,
            """
            [foo]
            bar = %(ENV:IDONTEXIST)s
            """,
        )
        with pytest.raises(configparser.InterpolationMissingOptionError):
            _ = Config("auxiliary")
