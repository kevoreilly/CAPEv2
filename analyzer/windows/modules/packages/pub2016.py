# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from winreg import HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_DWORD, CreateKeyEx, EnumKey, OpenKey, QueryInfoKey, SetValueEx

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class PUB2007(Package):
    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    """Word analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office*", "root", "Office16", "MSPUB.EXE"),
    ]

    def set_keys(self):

        baseOfficeKeyPath = r"Software\Microsoft\Office"
        installedVersions = []
        try:
            with OpenKey(HKEY_CURRENT_USER, baseOfficeKeyPath, 0, KEY_READ) as officeKey:
                for currentKey in range(QueryInfoKey(officeKey)[0]):
                    isVersion = True
                    officeVersion = EnumKey(officeKey, currentKey)
                    if "." in officeVersion:
                        for intCheck in officeVersion.split("."):
                            if not intCheck.isdigit():
                                isVersion = False
                                break
                        if isVersion:
                            installedVersions.append(officeVersion)
        except WindowsError:
            # Office isn't installed at all
            return

        for oVersion in installedVersions:
            with CreateKeyEx(HKEY_CURRENT_USER, rf"{baseOfficeKeyPath}\{oVersion}\Publisher\Security", 0, KEY_SET_VALUE) as key:
                SetValueEx(key, "VBAWarnings", 0, REG_DWORD, 1)
                SetValueEx(key, "AccessVBOM", 0, REG_DWORD, 1)
                SetValueEx(key, "ExtensionHardening", 0, REG_DWORD, 0)

    def start(self, path):
        self.set_keys()
        publisher = self.get_path_glob("MSPUB.EXE")
        path = check_file_extension(path, ".pub")
        return self.execute(publisher, f'"{path}"', path)
