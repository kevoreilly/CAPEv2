# Copyright (C) 2019 DoomedRaven
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import logging
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report


reporting_conf = Config("reporting")

HAVE_BINGRAPH = False
if reporting_conf.bingraph.on_demand is False:
    try:
        from binGraph.binGraph import generate_graphs as bingraph_gen

        HAVE_BINGRAPH = True
    except ImportError:
        HAVE_BINGRAPH = False

log = logging.getLogger(__name__)


bingraph_args_dict = {
    "recurse": False,
    "__dummy": False,
    "prefix": None,
    "json": False,
    "graphtitle": None,
    "showplt": False,
    "format": "svg",
    "figsize": (12, 4),
    "dpi": 100,
    "blob": False,
    "verbose": False,
    "graphtype": "ent",
    "chunks": 750,
    "ibytes": [{"name": "0s", "bytes": [0], "colour": (0.0, 1.0, 0.0, 1.0)}],
    "entcolour": "#ff00ff",
}

"""
path = ""
from binGraph.binGraph import generate_graphs as bingraph_gen
bingraph_args_dict.update({"files": [path], "save_dir": "/tmp"})
bingraph_gen(bingraph_args_dict)

"""


excluded_filetypes = (
    "HTML document, ASCII text, with CRLF line terminators",
    "ASCII text, with CRLF line terminators",
)


class BinGraph(Report):
    "Generate bingraphs"

    def run(self, results):
        if HAVE_BINGRAPH and reporting_conf.bingraph.enabled and reporting_conf.bingraph.on_demand is False:
            bingraph_path = os.path.join(self.analysis_path, "bingraph")
            if not os.path.exists(bingraph_path):
                os.makedirs(bingraph_path)
            try:
                if not os.listdir(bingraph_path) and results.get("target", {}).get("file", {}).get("sha256", False):
                    bingraph_args_dict.update(
                        {"prefix": results["target"]["file"]["sha256"], "files": [self.file_path], "save_dir": bingraph_path}
                    )
                    try:
                        bingraph_gen(bingraph_args_dict)
                    except Exception as e:
                        log.warning("Can't generate bingraph for {}: {}".format(self.file_path, e))
            except Exception as e:
                log.info(e)

            for key in ("dropped", "procdump"):
                for block in results.get(key, []) or []:
                    if (
                        block.get("size", 0) != 0
                        and block.get("type", "") not in excluded_filetypes
                        and not os.path.exists(os.path.join(bingraph_path, "{}-ent.svg".format(block["sha256"])))
                    ):
                        path = ""
                        if block.get("file", False):
                            path = block["file"]
                        elif block.get("path", False):
                            path = block["path"]
                        if not path:
                            continue
                        bingraph_args_dict.update({"prefix": block["sha256"], "files": [path], "save_dir": bingraph_path})
                        try:
                            bingraph_gen(bingraph_args_dict)
                        except Exception as e:
                            log.warning("Can't generate report for {}: {}".format(path, e))

                for block in results.get("CAPE", {}).get("payloads") or []:
                    if (
                        block.get("size", 0) != 0
                        and block.get("type", "") not in excluded_filetypes
                        and not os.path.exists(os.path.join(bingraph_path, "{}-ent.svg".format(block["sha256"])))
                    ):
                        path = ""
                        if block.get("file", False):
                            path = block["file"]
                        elif block.get("path", False):
                            path = block["path"]
                        if not path:
                            continue
                        bingraph_args_dict.update({"prefix": block["sha256"], "files": [path], "save_dir": bingraph_path})
                        try:
                            bingraph_gen(bingraph_args_dict)
                        except Exception as e:
                            log.warning("Can't generate report for {}: {}".format(path, e))
