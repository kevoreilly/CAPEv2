# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_mkdir

log = logging.getLogger(__name__)

processing_conf = Config("processing")

HAVE_VBA2GRAPH = False
if processing_conf.vba2graph.enabled:
    try:
        from lib.cuckoo.common.office.vba2graph import vba2graph_from_vba_object, vba2graph_gen

        HAVE_VBA2GRAPH = True
    except ImportError:
        HAVE_VBA2GRAPH = False


def vba2graph_func(file_path: str, id: str, sha256: str, on_demand: bool = False):
    if HAVE_VBA2GRAPH and processing_conf.vba2graph.enabled and (not processing_conf.vba2graph.on_demand or on_demand):
        try:
            vba2graph_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", id, "vba2graph")
            vba2graph_svg_path = os.path.join(vba2graph_path, f"{sha256}.svg")
            if path_exists(vba2graph_svg_path):
                return
            if not path_exists(vba2graph_path):
                path_mkdir(vba2graph_path)
            vba_code = vba2graph_from_vba_object(file_path)
            if vba_code:
                vba2graph_gen(vba_code, vba2graph_path)
        except Exception as e:
            log.info(e)
