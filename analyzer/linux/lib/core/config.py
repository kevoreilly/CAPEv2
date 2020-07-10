# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import configparser


class Config:
    def __init__(self, cfg):
        """@param cfg: configuration file."""
        config = configparser.ConfigParser(allow_no_value=True)
        config.read(cfg)
        for section in config.sections():
            for name, raw_value in config.items(section):
                if name == "file_name":
                    value = config.get(section, name)
                    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
                        value = value[1:-1]
                elif name == "options":
                    value = self.parse_options(config.get(section, name))
                else:
                    try:
                        value = config.getboolean(section, name)
                    except ValueError:
                        try:
                            value = config.getint(section, name)
                        except ValueError:
                            value = config.get(section, name)
                setattr(self, name, value)

        # Just make sure the options field is available.
        if not hasattr(self, "options"):
            self.options = {}

    def get(self, name, default=None):
        if hasattr(self, name):
            return getattr(self, name)
        return default

    def get_options(self):
        """Get analysis options.
        @return: options dict.
        """
        # The analysis package can be provided with some options in the
        # following format:
        #   option1=value1,option2=value2,option3=value3
        #
        # Here we parse such options and provide a dictionary that will be made
        # accessible to the analysis package.
        options = {}
        if hasattr(self, "options") and isinstance(self.options, str):
            # Split the options by comma.
            fields = self.options.split(",")
            for field in fields:
                # Split the name and the value of the option.
                key, value = field.split("=", 1)
                # If the parsing went good, we add the option to the dictionary.
                options[key.strip()] = value.strip()

        return options

    def parse_options(self, options):
        """Get analysis options.
        @return: options dict.
        """
        # The analysis package can be provided with some options in the
        # following format:
        #   option1=value1,option2=value2,option3=value3
        ret = {}
        for field in options.split(","):
            if "=" not in field:
                continue

            key, value = field.split("=", 1)
            ret[key.strip()] = value.strip()
        return ret
