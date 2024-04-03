# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import configparser
import glob
import os
from typing import Dict, Iterable

from lib.cuckoo.common.colors import bold, red
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUSTOM_CONF_DIR
from lib.cuckoo.common.dictionary import Dictionary
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooOperationalError


def parse_options(options: str) -> Dict[str, str]:
    """Parse the analysis options field to a dictionary."""
    ret = {}
    for field in options.split(","):
        if "=" not in field:
            continue

        key, value = field.split("=", 1)
        ret[key.strip()] = value.strip()
    return ret


class _BaseConfig:
    """Configuration file parser."""

    def __init__(self):
        self.fullconfig = None
        self.refresh()

    def _get_files_to_read(self):
        raise NotImplementedError

    def get(self, section):
        """Get options for the given section.
        @param section: section to fetch.
        @raise CuckooOperationalError: if section not found.
        @return: dict of option key/values.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            raise CuckooOperationalError(f"Option {section} is not found in configuration, error: {e}") from e

    def get_config(self):
        return self.fullconfig

    def refresh(self):
        self.fullconfig = self._read_files(self._get_files_to_read())._sections

    def _read_files(self, files: Iterable[str]):
        # Escape the percent signs so that ConfigParser doesn't try to do
        # interpolation of the value as well.
        config = configparser.ConfigParser({f"ENV:{key}": val.replace("%", "%%") for key, val in os.environ.items()})

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
            raise

        for section in config.sections():
            dct = Dictionary()
            for name, value in config.items(section):
                if name.startswith("env:"):
                    continue
                try:
                    # Ugly fix to avoid '0' and '1' to be parsed as a boolean value.
                    # We raise an exception to parse it as an integer.
                    if value in {"0", "1"}:
                        raise ValueError

                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(dct, name, value)
            setattr(self, section, dct)

        return config


class ConfigMeta(type):
    """Only create one instance of a Config for each (non-analysis) config file."""

    configs = {}

    def __call__(self, fname_base: str = "cuckoo"):
        if fname_base not in self.configs:
            self.configs[fname_base] = super(ConfigMeta, self).__call__(fname_base=fname_base)

        return self.configs[fname_base]

    @classmethod
    def refresh(cls):
        """This should really only be needed for testing."""
        for config in cls.configs.values():
            config.refresh()


class Config(_BaseConfig, metaclass=ConfigMeta):
    def __init__(self, fname_base: str = "cuckoo"):
        self._fname_base = fname_base
        super().__init__()

    def _get_files_to_read(self):
        # Allows test workflows to ignore custom root configs
        include_root_configs = "CAPE_DISABLE_ROOT_CONFIGS" not in os.environ
        files = [os.path.join(CUCKOO_ROOT, "conf", "default", f"{self._fname_base}.conf.default")]
        if include_root_configs:
            files.append(os.path.join(CUCKOO_ROOT, "conf", f"{self._fname_base}.conf"))
            files.extend(sorted(glob.glob(os.path.join(CUCKOO_ROOT, "conf", f"{self._fname_base}.conf.d", "*.conf"))))
        files.append(os.path.join(CUSTOM_CONF_DIR, f"{self._fname_base}.conf"))
        files.extend(sorted(glob.glob(os.path.join(CUSTOM_CONF_DIR, f"{self._fname_base}.conf.d", "*.conf"))))

        if "CAPE_CD" in os.environ:
            files.append(os.path.join(os.environ["CAPE_CD"], f"{self._fname_base}.conf"))

        if not files:
            raise CuckooCriticalError(f"No {self._fname_base} config files could be found!")
        return files


class AnalysisConfig(_BaseConfig):
    def __init__(self, cfg="analysis.conf"):
        self._cfg = cfg
        super().__init__()

    def _get_files_to_read(self):
        return (self._cfg,)
