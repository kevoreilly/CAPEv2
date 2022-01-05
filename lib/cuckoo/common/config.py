# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import configparser
import os

from lib.cuckoo.common.colors import bold, red
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooConfigNotInitializedError, CuckooOperationalError
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
    return ",".join("%s=%s" % (k, v) for k, v in sorted(options.items()))


class _BaseConfig:
    """Configuration file parser."""

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise CuckooOperationalError: if section not found.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            raise CuckooOperationalError(
                "Option %s is not found in configuration, error: %s" % (section, e)
            )

    def get_config(self):
        return self.fullconfig

    def _read_files(self, files):
        config = configparser.ConfigParser()
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
                try:
                    # Ugly fix to avoid '0' and '1' to be parsed as a
                    # boolean value.
                    # We raise an exception to goto fail^w parse it
                    # as integer.
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


NOT_SET = object()


class ConfigMeta(type):
    """Only create one instance of a Config for each (non-analysis) config file."""

    configs = {}

    def __call__(cls, file_name="cuckoo"):
        if file_name not in cls.configs:
            cls.configs[file_name] = super(ConfigMeta, cls).__call__(
                file_name=file_name
            )
        return cls.configs[file_name]

    @classmethod
    def reset(cls):
        """This should really only be needed for testing."""
        cls.configs.clear()


class Config(_BaseConfig, metaclass=ConfigMeta):
    config_dirs = NOT_SET

    def __init__(self, file_name="cuckoo"):
        if self.__class__.config_dirs is NOT_SET:
            raise CuckooConfigNotInitializedError()
        files = [os.path.join(CUCKOO_ROOT, "conf", f"{file_name}.conf")]
        for config_dir in self.config_dirs:
            files.append(os.path.join(config_dir, f"{file_name}.conf"))
        self._read_files(files)

    @classmethod
    def initialize(cls, config_dirs=None):
        if config_dirs is None:
            config_dirs = []
        for config_dir in config_dirs:
            if not os.path.isdir(config_dir):
                raise OSError(f"{config_dir} does not exist")
        cls.config_dirs = config_dirs


class AnalysisConfig(_BaseConfig):
    def __init__(self, cfg="analysis.conf"):
        files = (cfg,)
        self._read_files(files)
