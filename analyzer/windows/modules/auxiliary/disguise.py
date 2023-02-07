# Copyright (C) 2010-2016 Cuckoo Foundation., KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import itertools
import logging
import os
import re
import subprocess
from random import randint
from uuid import uuid4
from winreg import (
    HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE,
    KEY_READ,
    KEY_SET_VALUE,
    KEY_WOW64_64KEY,
    REG_DWORD,
    REG_SZ,
    CreateKeyEx,
    EnumKey,
    EnumValue,
    OpenKey,
    QueryInfoKey,
    SetValueEx,
)

from lib.common.abstracts import Auxiliary
from lib.common.rand import random_integer, random_string

log = logging.getLogger(__name__)
PERSISTENT_ROUTE_GATEWAY = "192.168.1.1"
si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW


class Disguise(Auxiliary):
    """Disguise the analysis environment."""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.disguise
        self.config = config

    @staticmethod
    def run_as_system(command):
        if not command:
            return None
        elif not isinstance(command, list):
            command = [command]

        psexec_path = os.path.join(os.getcwd(), "bin", "psexec.exe")
        if not os.path.exists(psexec_path):
            log.warning("PsExec executable was not found in bin/")

        output = None
        try:
            output = subprocess.check_output(
                [psexec_path, "-accepteula", "-nobanner", "-s"] + command, stderr=subprocess.STDOUT, startupinfo=si
            )
        except subprocess.CalledProcessError as e:
            log.error(e.output)

        return output

    def disable_scs(self):
        """Put here all sc related configuration"""
        commands = [["sc", "stop", "ClickToRunSvc"], ["sc", "config", "ClickToRunSvc", "start=", "disabled"]]
        for command in commands:
            try:
                subprocess.check_output(command, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                log.error(e.output)

    def change_productid(self):
        """Randomizes Windows ProductId.
        The Windows ProductId is occasionally used by malware
        to detect public setups of Cuckoo, e.g., Malwr.com.
        """
        value = f"{random_integer(5)}-{random_integer(3)}-{random_integer(7)}-{random_integer(5)}"
        with OpenKey(
            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_SET_VALUE | KEY_WOW64_64KEY
        ) as key:
            SetValueEx(key, "ProductId", 0, REG_SZ, value)

    def _office_helper(self, key, subkey, value, size=REG_SZ):
        with OpenKey(HKEY_CURRENT_USER, key, 0, KEY_SET_VALUE) as tmp_key:
            SetValueEx(tmp_key, subkey, 0, size, value)

    def set_office_params(self):
        baseOfficeKeyPath = r"Software\Microsoft\Office"
        installedVersions = []

        try:
            with OpenKey(HKEY_CURRENT_USER, baseOfficeKeyPath, 0, KEY_READ) as officeKey:
                for currentKey in range(QueryInfoKey(officeKey)[0]):
                    officeVersion = EnumKey(officeKey, currentKey)
                    if "." in officeVersion:
                        isVersion = all(intCheck.isdigit() for intCheck in officeVersion.split("."))
                        if isVersion:
                            installedVersions.append(officeVersion)
        except WindowsError:
            # Office isn't installed at all
            return

        self._office_helper("Software\\Microsoft\\Office\\Common\\Security", "DisableAllActiveX", REG_DWORD, 0)
        self._office_helper("Software\\Microsoft\\Office\\Common\\Security", "UFIControls", REG_DWORD, 1)
        for oVersion in installedVersions:
            for software in ("Word", "Excel", "PowerPoint", "Publisher", "Outlook"):
                productPath = rf"{baseOfficeKeyPath}\{oVersion}\{software}"
                self._office_helper(f"{productPath}\\Common\\General", "ShownOptIn", REG_DWORD, 1)
                self._office_helper(f"{productPath}\\Security", "VBAWarnings", REG_DWORD, 1)
                self._office_helper(f"{productPath}\\Security", "AccessVBOM", REG_DWORD, 1)
                self._office_helper(f"{productPath}\\Security", "DisableDDEServerLaunch", REG_DWORD, 0)
                self._office_helper(f"{productPath}\\Security", "MarkInternalAsUnsafe", REG_DWORD, 0)
                self._office_helper(f"{productPath}\\Security\\ProtectedView", "DisableAttachmentsInPV", REG_DWORD, 1)
                self._office_helper(f"{productPath}\\Security\\ProtectedView", "DisableInternetFilesInPV", REG_DWORD, 1)
                self._office_helper(f"{productPath}\\Security\\ProtectedView", "DisableUnsafeLocationsInPV", REG_DWORD, 1)
                # self._office_helper(f"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Office\\{oVersion}\\{software}\\Security", "MarkInternalAsUnsafe", REG_DWORD, 0)
                self._office_helper(f"{productPath}\\Security", "ExtensionHardening", 0)

    def set_office_mrus(self):
        """Adds randomized MRU's to Office software(s).
        Occasionally used by macros to detect sandbox environments.
        """
        baseOfficeKeyPath = r"Software\Microsoft\Office"
        installedVersions = []
        basePaths = [
            "C:\\",
            "C:\\Windows\\Logs\\",
            "C:\\Windows\\Temp\\",
            "C:\\Program Files\\",
        ]
        extensions = {
            "Word": ["doc", "docx", "docm", "rtf"],
            "Excel": ["xls", "xlsx", "csv"],
            "PowerPoint": ["ppt", "pptx"],
        }
        try:
            with OpenKey(HKEY_CURRENT_USER, baseOfficeKeyPath, 0, KEY_READ) as officeKey:
                for currentKey in range(QueryInfoKey(officeKey)[0]):
                    officeVersion = EnumKey(officeKey, currentKey)
                    if "." in officeVersion:
                        isVersion = all(intCheck.isdigit() for intCheck in officeVersion.split("."))
                        if isVersion:
                            installedVersions.append(officeVersion)
        except WindowsError:
            # Office isn't installed at all
            return

        for oVersion, software in itertools.product(installedVersions, extensions):
            values = []
            mruKeyPath = ""
            productPath = rf"{baseOfficeKeyPath}\{oVersion}\{software}"
            try:
                with OpenKey(HKEY_CURRENT_USER, productPath, 0, KEY_READ):
                    pass
                mruKeyPath = rf"{productPath}\File MRU"
                with CreateKeyEx(HKEY_CURRENT_USER, mruKeyPath, 0, KEY_READ) as mruKey:
                    displayValue = False
                    for mruKeyInfo in range(QueryInfoKey(mruKey)[1]):
                        currentValue = EnumValue(mruKey, mruKeyInfo)
                        if currentValue[0] == "Max Display":
                            displayValue = True
                        values.append(currentValue)
            except WindowsError:
                # An Office version was found in the registry but the
                # software (Word/Excel/PowerPoint) was not installed.
                values = "notinstalled"

            if values != "notinstalled" and len(values) < 5:
                with OpenKey(HKEY_CURRENT_USER, mruKeyPath, 0, KEY_SET_VALUE) as mruKey:
                    if not displayValue:
                        SetValueEx(mruKey, "Max Display", 0, REG_DWORD, 25)

                    for i in range(1, randint(10, 30)):
                        rString = random_string(minimum=11, charset="0123456789ABCDEF")
                        baseId = f"T01D1C{rString}" if i % 2 else f"T01D1D{rString}"
                        setVal = "[F00000000][{0}][O00000000]*{1}{2}.{3}".format(
                            baseId,
                            basePaths[randint(0, len(basePaths) - 1)],
                            random_string(minimum=3, maximum=15, charset="abcdefghijkLMNOPQURSTUVwxyz_0369"),
                            extensions[software][randint(0, len(extensions[software]) - 1)],
                        )
                        name = f"Item {i}"
                        SetValueEx(mruKey, name, 0, REG_SZ, setVal)

    def ramnit(self):
        with OpenKey(
            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_SET_VALUE | KEY_WOW64_64KEY
        ) as key:
            SetValueEx(key, "jfghdug_ooetvtgk", 0, REG_SZ, "TRUE")

    """
    def netbios(self):
        try:
            # get netbios interface
            for path in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
                netbios_init = f"System\\{path}\\Services\\NetBT\\Parameters\\Interfaces\\"
                with OpenKey(HKEY_LOCAL_MACHINE, netbios_init,0, KEY_READ) as netbios:
                    for currentKey in range(QueryInfoKey(netbios)[0]):
                        subkey = EnumKey(netbios, currentKey)
                        if  subkey.startswith("Tcpip_"):
                            with OpenKey(HKEY_LOCAL_MACHINE, f"{netbios_init}\\{subkey}", 0, KEY_SET_VALUE) as sub_netbios:
                                SetValueEx(sub_netbios, "NetbiosOptions", 0, REG_DWORD, 2)

            # disable lmhosts
            with OpenKey(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\NetBT\\Parameters\\", 0, KEY_SET_VALUE) as lmhosts:
                SetValueEx(lmhosts, "EnableLMHOSTS", 0, REG_DWORD, 0)

        except Exception as e:
            print(e)
    """

    def replace_reg_strings(self, regkey):
        regcmd = "C:\\Windows\\System32\\reg.exe"
        filepath = os.path.join("C:\\Windows\\Temp", regkey.rstrip("\\").rsplit("\\", 1)[-1] + ".reg")

        self.run_as_system([regcmd, "export", regkey, filepath, "/y"])

        with io.open(filepath, "r", encoding="utf-16") as f:
            data = f.read()

        # replace all references to VMs
        data = re.sub(r"qemu|vbox|vmware|virtual", lambda x: (x.end() - x.start()) * "_", data, flags=re.IGNORECASE)

        with io.open(filepath, "w", encoding="utf-16") as f:
            f.write(data)

        self.run_as_system([regcmd, "delete", regkey, "/f"])
        self.run_as_system([regcmd, "import", filepath])

        os.remove(filepath)

    def randomizeUUID(self):
        createdUUID = str(uuid4())

        log.info("Disguising GUID to %s", createdUUID)
        keyPath = "SOFTWARE\\Microsoft\\Cryptography"

        with OpenKey(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE | KEY_WOW64_64KEY) as key:
            # Replace the UUID with the new UUID
            SetValueEx(key, "MachineGuid", 0, REG_SZ, createdUUID)

    def add_persistent_route(self):
        self.run_as_system(["C:\\Windows\\System32\ROUTE.exe", "-p", "add", "0.0.0.0", "mask", "0.0.0.0", PERSISTENT_ROUTE_GATEWAY])
        self.run_as_system(
            ["C:\\Windows\\System32\ROUTE.exe", "-p", "change", "0.0.0.0", "mask", "0.0.0.0", PERSISTENT_ROUTE_GATEWAY]
        )

    def start(self):
        if self.config.windows_static_route:
            log.info(f"Config for route is: {str(self.config.windows_static_route)}")
            self.add_persistent_route()
        self.change_productid()
        self.set_office_mrus()
        self.ramnit()
        self.randomizeUUID()
        # self.disable_scs()
        # self.netbios()
        # self.replace_reg_strings('HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE')
        # self.replace_reg_strings('HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI')

        return True
