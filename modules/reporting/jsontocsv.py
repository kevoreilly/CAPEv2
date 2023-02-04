# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
from collections import MutableMapping

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class JsonToCSV(Report):
    """Saves analysis results in JSON format."""

    # ensure we run after the JsonDUMP
    order = 9

    def flatten(self, dictionary, parent_key=False, separator='.'):
        """
        Turn a nested dictionary into a flattened dictionary
        :param dictionary: The dictionary to flatten
        :param parent_key: The string to prepend to dictionary's keys
        :param separator: The string used to separate flattened keys
        :return: A flattened dictionary
        """

        items = []
        for key, value in dictionary.items():
            new_key = str(parent_key) + separator + key if parent_key else key
            if isinstance(value, MutableMapping):
                if not value.items():
                    items.append((new_key,None))
                else:
                    items.extend(self.flatten(value, new_key, separator).items())
            elif isinstance(value, list):
                if len(value):
                    for k, v in enumerate(value):
                        items.extend(self.flatten({str(k): v}, new_key).items())
                else:
                    items.append((new_key,None))
            else:
                items.append((new_key, value))
        return dict(items)

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        # Get list of keys to exclude in the CSV Report (default keys to be skipped are statistics, debug, deduplicated, shots)
        excludes_keys = self.options.get("keys_to_exclude", "statistics,debug,deduplicated,shots")
        excludes_list = excludes_keys.split(",")
        jsonpath = os.path.join(self.reports_path, "report.json")
        csvpath = os.path.join(self.reports_path, "report.csv")

        try:
            with open(jsonpath, "r") as openjson:
                report_dict = json.load(openjson)
            flattened_report_dict = self.flatten(report_dict)
            filtered_report_dict = {key : val for key, val in flattened_report_dict.items() if not any(ele in key for ele in excludes_list)}
            with open(csvpath, 'w') as report:
                for key in filtered_report_dict.keys():
                    report.write("%s, %s\n" % (key, filtered_report_dict[key]))      
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError(f"Failed to convert JSON report into CSV Report: {e}")
