# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
from lib.common.abstracts import Package

from winreg import (
    OpenKey,
    CreateKeyEx,
    SetValueEx,
    CloseKey,
    QueryInfoKey,
    EnumKey,
    EnumValue,
    HKEY_LOCAL_MACHINE,
    HKEY_CURRENT_USER,
    KEY_SET_VALUE,
    KEY_READ,
    REG_SZ,
    REG_DWORD,
)


class PUB(Package):
    """Word analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "MSPUB.EXE"),
    ]

    def set_keys(self):

        baseOfficeKeyPath = r"Software\Microsoft\Office"
        installedVersions = list()
        try:
            officeKey = OpenKey(HKEY_CURRENT_USER, baseOfficeKeyPath, 0, KEY_READ)
            for currentKey in range(0, QueryInfoKey(officeKey)[0]):
                isVersion = True
                officeVersion = EnumKey(officeKey, currentKey)
                if "." in officeVersion:
                    for intCheck in officeVersion.split("."):
                        if not intCheck.isdigit():
                            isVersion = False
                            break

                    if isVersion:
                        installedVersions.append(officeVersion)
            CloseKey(officeKey)
        except WindowsError:
            # Office isn't installed at all
            return

        for oVersion in installedVersions:
            key = CreateKeyEx(HKEY_CURRENT_USER, r"{0}\{1}\Publisher\Security".format(baseOfficeKeyPath, oVersion), 0, KEY_SET_VALUE)

            SetValueEx(key, "VBAWarnings", 0, REG_DWORD, 1)
            SetValueEx(key, "AccessVBOM", 0, REG_DWORD, 1)
            SetValueEx(key, "ExtensionHardening", 0, REG_DWORD, 0)
            CloseKey(key)

    def start(self, path):
        self.set_keys()
        publisher = self.get_path_glob("Microsoft Office Publisher")
        if not path.endswith(".pub"):
            os.rename(path, path + ".pub")
            path += ".pub"
        return self.execute(publisher, '"%s"' % path, path)
