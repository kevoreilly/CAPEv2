# Copyright (C) 2019 DoomedRaven
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_exists, path_mkdir

reporting_conf = Config("reporting")

HAVE_BINGRAPH = False
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
        bingraph_cfg = reporting_conf.bingraph
        if HAVE_BINGRAPH and bingraph_cfg.enabled and not bingraph_cfg.on_demand:
            bingraph_path = os.path.join(self.analysis_path, "bingraph")
            if not path_exists(bingraph_path):
                path_mkdir(bingraph_path)
            if getattr(bingraph_cfg, "binary", True) is not False:
                try:
                    target_sha256 = results.get("target", {}).get("file", {}).get("sha256", False)
                    if not os.listdir(bingraph_path) and target_sha256 and path_exists(self.file_path):
                        try:
                            bingraph_gen(
                                {
                                    **bingraph_args_dict,
                                    "prefix": target_sha256,
                                    "files": [self.file_path],
                                    "save_dir": bingraph_path,
                                }
                            )
                        except Exception as e:
                            log.warning("Can't generate bingraph for %s: %s", self.file_path, e)
                except Exception as e:
                    log.info(e)

            blocks = list(results.get("dropped", []) or [])
            if getattr(bingraph_cfg, "procdump", True) is not False:
                blocks.extend(results.get("procdump", []) or [])
            if getattr(bingraph_cfg, "cape", True) is not False:
                blocks.extend(results.get("CAPE", {}).get("payloads") or [])

            for block in blocks:
                sha256 = block.get("sha256")
                if (
                    sha256
                    and block.get("size", 0) != 0
                    and block.get("type", "") not in excluded_filetypes
                    and not path_exists(os.path.join(bingraph_path, f"{sha256}-ent.svg"))
                ):
                    path = block.get("file") or block.get("path") or ""
                    if not path or not path_exists(path):
                        continue
                    try:
                        bingraph_gen({**bingraph_args_dict, "prefix": sha256, "files": [path], "save_dir": bingraph_path})
                    except Exception as e:
                        log.warning("Can't generate report for %s: %s", path, e)
