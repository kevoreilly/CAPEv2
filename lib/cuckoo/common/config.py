# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import configparser
import glob
import os

from lib.cuckoo.common.colors import bold, red
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUSTOM_CONF_DIR
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.objects import Dictionary


def parse_options(options):
    """Parse the analysis options field to a dictionary."""
    ret = {}
    for field in options.split(","):
        if "=" not in field:
            continue

        key, value = field.split("=", 1)
        ret[key.strip()] = value.strip()
    return ret


def emit_options(options):
    """Emit the analysis options from a dictionary to a string."""
    return ",".join(f"{k}={v}" for k, v in sorted(options.items()))


class _BaseConfig:
    """Configuration file parser."""

    def get(self, section):
        """Get options for the given section.
        @param section: section to fetch.
        @raise CuckooOperationalError: if section not found.
        @return: dict of option key/values.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            raise CuckooOperationalError(f"Option {section} is not found in configuration, error: {e}")

    def get_config(self):
        return self.fullconfig

    def _read_files(self, files):
        config = configparser.ConfigParser(
            # Escape the percent signs so that ConfigParser doesn't try to do
            # interpolation of the value as well.
            dict((f"ENV:{key}", val.replace("%", "%%")) for key, val in os.environ.items())
        )
        try:
            config.read(files)
        except UnicodeDecodeError as e:
            print(
                bold(
                    red(
                        f"please fix your config file(s): {', '.join(files)} - "
                        f"Pay attention for bytes c2 xa - {e.object}\n\n{e.reason}"
                    )
                )
            )
            raise UnicodeDecodeError

        self.fullconfig = config._sections

        for section in config.sections():
            dct = Dictionary()
            for name, _ in config.items(section):
                if name.startswith("env:"):
                    continue
                try:
                    # Ugly fix to avoid '0' and '1' to be parsed as a boolean value.
                    # We raise an exception to goto fail^w parse it as integer.
                    if config.get(section, name) in ["0", "1"]:
                        raise ValueError

                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(dct, name, value)
            setattr(self, section, dct)


class ConfigMeta(type):
    """Only create one instance of a Config for each (non-analysis) config file."""

    configs = {}

    def __call__(cls, fname_base="cuckoo"):
        if fname_base not in cls.configs:
            cls.configs[fname_base] = super(ConfigMeta, cls).__call__(fname_base=fname_base)
        return cls.configs[fname_base]

    @classmethod
    def reset(cls):
        """This should really only be needed for testing."""
        cls.configs.clear()


class Config(_BaseConfig, metaclass=ConfigMeta):
    def __init__(self, fname_base="cuckoo"):
        files = self._get_files_to_read(fname_base)
        self._read_files(files)

    def _get_files_to_read(self, fname_base):
        files = [
            os.path.join(CUCKOO_ROOT, "conf", f"{fname_base}.conf"),
            os.path.join(CUSTOM_CONF_DIR, f"{fname_base}.conf"),
        ]
        files.extend(sorted(glob.glob(os.path.join(CUSTOM_CONF_DIR, f"{fname_base}.conf.d", "*.conf"))))
        return files


class AnalysisConfig(_BaseConfig):
    def __init__(self, cfg="analysis.conf"):
        files = (cfg,)
        self._read_files(files)
