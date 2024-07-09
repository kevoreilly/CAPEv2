# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time

from lib.api.utils import Utils
from lib.common.abstracts import Package

_OPT_OFFICE = "office"
_OPT_NO_IAT = "no-iat"
_OPT_YARASCAN = "yarascan"

util = Utils()


class ONE(Package):
    """OneNote analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options
        # self.options["exclude-apis"] = "memcpy"
        self.options[_OPT_OFFICE] = 1
        self.options[_OPT_YARASCAN] = 0
        self.options[_OPT_NO_IAT] = 1

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "ONENOTE.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "ONENOTE.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "ONENOTE.EXE"),
    ]
    summary = "Open a sample file with ONENOTE.EXE."
    description = f"""Use 'ONENOTE.EXE /nologo /navigate <sample>'
    to open a onenote .one file.
    Set option '{_OPT_YARASCAN}=0' is disabled.
    Set options '{_OPT_OFFICE}=1' and '{_OPT_NO_IAT}=1'.
    Before execution, modify the registry entries LowRiskFileTypes and DefaultFileTypeRisk,
    to encourage detonation.
    The .one filename extension will be added automatically."""

    def start(self, path):
        onenote = self.get_path_glob("ONENOTE.EXE")
        if "." not in os.path.basename(path):
            new_path = f"{path}.one"
            os.rename(path, new_path)
            path = new_path

        util.cmd_wrapper(
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "LowRiskFileTypes" /t REG_SZ /d ".ade;.adp;.app;.asp;.bas;.bat;.cer;.chm;.cmd;.com;.cpl;.crt;.csh;.exe;.fxp;.hlp;.hta;.inf;.ins;.isp;.its;.js;.jse;.ksh;.lnk;.mad;.maf;.mag;.mam;.maq;.mar;.mas;.mat;.mau;.mav;.maw;.mda;.mdb;.mde;.mdt;.mdw;.mdz;.msc;.msi;.msp;.mst;.ops;.pcd;.pif;.prf;.prg;.pst;.reg;.scf;.scr;.sct;.shb;.shs;.tmp;.url;.vb;.vbe;.vbs;.vsmacros;.vss;.vst;.vsw;.ws;.wsc;.wsf;.wsh;" /f'
        )
        util.cmd_wrapper(
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "1808" /f'
        )
        util.cmd_wrapper(
            r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ef87b4cb-f2ce-4785-8658-4ca6c63e38c6}" /f'
        )
        time.sleep(3)
        return self.execute(onenote, f"/nologo /navigate {path}", path)
