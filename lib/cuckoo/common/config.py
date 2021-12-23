# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import configparser

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.objects import Dictionary
from lib.cuckoo.common.colors import red, bold


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


class Config:
    """Configuration file parser."""

    def __init__(self, file_name="cuckoo", cfg=None):
        """
        @param file_name: file name without extension.
        @param cfg: configuration file path.
        """
        config = configparser.ConfigParser()

        if cfg:
            config.read(cfg)
        else:
            try:
                config.read(os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % file_name))
            except UnicodeDecodeError as e:
                print(
                    bold(
                        red(
                            "please fix your config file: {}.conf - Pay attention for bytes c2 xa - {}\n\n{}".format(
                                file_name, e.object, e.reason
                            )
                        )
                    )
                )
                raise UnicodeDecodeError

        self.fullconfig = config._sections

        for section in config.sections():
            setattr(self, section, Dictionary())
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

                setattr(getattr(self, section), name, value)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise CuckooOperationalError: if section not found.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            raise CuckooOperationalError("Option %s is not found in " "configuration, error: %s" % (section, e))

    def get_config(self):
        return self.fullconfig
