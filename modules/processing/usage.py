# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_write_file

try:
    import pygal

    HAVE_PYGAL = True
except ImportError:
    HAVE_PYGAL = False


class Usage(Processing):
    """Converts collected usage data to image for web display
    and performs other processing on usage data
    """

    def run(self):
        self.key = "usage"
        usage = {}

        if not HAVE_PYGAL:
            return usage

        aux_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.results["info"]["id"]), "aux")
        usage_log = os.path.join(aux_path, "usage.log")
        if not path_exists(usage_log):
            return usage

        with open(usage_log, "r") as f:
            lines = [x.strip().split(" ") for x in f.readlines()]
        if not lines:
            return usage

        mem_points, cpu_points = list(zip(*lines))
        mem_points = [int(x) for x in mem_points]
        cpu_points = [int(x) for x in cpu_points]

        usage["log"] = usage_log

        line_chart = pygal.Line(
            fill=True, height=150, range=[0, 100], y_labels_major_every=1, show_dots=False, y_labels=[0, 25, 50, 75, 100]
        )
        line_chart.add("CPU", cpu_points)
        line_chart.add("MEM", mem_points)

        data = line_chart.render()

        usage_svg = os.path.join(aux_path, "usage.svg")
        _ = path_write_file(usage_svg, data)

        usage["cpu_usage"] = cpu_points
        usage["mem_usage"] = mem_points
        usage["file"] = usage_svg

        return usage
