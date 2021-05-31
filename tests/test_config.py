# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import tempfile
import pytest
import os

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooOperationalError


@pytest.fixture
def config():
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
    path = tempfile.mkstemp()[1]
    with open(path, mode="w") as file:
        file.write(CONF_EXAMPLE)

    yield Config(cfg=path)
    print(path)
    os.remove(path)


class TestConfig:
    def test_get_option_exist(self, config):

        """Fetch an option of each type from default config file."""
        assert config.get("cuckoo")["debug"] is False
        assert config.get("cuckoo")["tcpdump"] == "/usr/sbin/tcpdump"
        assert config.get("cuckoo")["critical_timeout"] == 600

    def test_config_file_not_found(self, config):
        assert Config("foo")

    def test_get_option_not_found(self, config):
        with pytest.raises(CuckooOperationalError):
            config.get("foo")

    def test_get_option_not_found_in_file_not_found(self, config):
        with pytest.raises(CuckooOperationalError):
            config = Config("bar")
            config.get("foo")
