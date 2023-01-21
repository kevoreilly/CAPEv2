# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists, path_mkdir, path_write_file

log = logging.getLogger(__name__)

processing_conf = Config("processing")

"""
path = "/opt/CAPEv2/storage/analyses/2894126/binary"
task_id = 2894126
from lib.cuckoo.common.integrations.XLMMacroDeobfuscator import xlmdeobfuscate
details = xlmdeobfuscate(path, task_id, on_demand=True)
"""

HAVE_XLM_DEOBF = False
if processing_conf.xlsdeobf.enabled:
    try:
        HAVE_XLM_DEOBF = True
        from XLMMacroDeobfuscator.deobfuscator import process_file as XLMMacroDeobf
    except ImportError:
        print(
            "Missed dependey XLMMacroDeobfuscator: pip3 install -U git+https://github.com/DissectMalware/XLMMacroDeobfuscator.git"
        )

    xlm_kwargs = {
        # "file": filepath,
        "noninteractive": True,
        "extract_only": False,
        "start_with_shell": False,
        "return_deobfuscated": True,
        "no_indent": False,
        "output_formula_format": "CELL:[[CELL-ADDR]], [[STATUS]], [[INT-FORMULA]]",
        "day": -1,
        # "password": password,
    }


def xlmdeobfuscate(filepath: str, task_id: str, password: str = "", on_demand: bool = False):

    if not HAVE_XLM_DEOBF or processing_conf.xlsdeobf.on_demand and not on_demand:
        return
    xlm_kwargs["file"] = filepath
    xlm_kwargs["password"] = password

    macro_folder = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "macros")

    try:
        deofuscated_xlm = XLMMacroDeobf(**xlm_kwargs)
        if deofuscated_xlm:
            xlmmacro = {"Code": deofuscated_xlm}
            if not path_exists(macro_folder):
                path_mkdir(macro_folder)
            macro_file = os.path.join(macro_folder, "xlm_macro")
            _ = path_write_file(macro_file, "\n".join(deofuscated_xlm), mode="text")
            xlmmacro["info"] = {"yara_macro": File(macro_file).get_yara(category="macro")}
            xlmmacro["info"]["yara_macro"].extend(File(macro_file).get_yara(category="CAPE"))
            return xlmmacro
    except Exception as e:
        if "no attribute 'workbook'" in str(e) or "Can't find workbook" in str(e):
            log.info("Workbook not found. Probably not an Excel file")
        else:
            log.error(e, exc_info=True)
