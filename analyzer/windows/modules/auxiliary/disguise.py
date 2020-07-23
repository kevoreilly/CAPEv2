# Copyright (C) 2010-2016 Cuckoo Foundation., KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import io
import os
import re
import subprocess
import logging
from random import randint
from winreg import *
from uuid import uuid4
import platform

from lib.common.abstracts import Auxiliary
from lib.common.rand import random_integer, random_string

log = logging.getLogger(__name__)


class Disguise(Auxiliary):
    """Disguise the analysis environment."""

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
            output = subprocess.check_output([psexec_path, "-accepteula", "-nobanner", "-s"] + command, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error(e.output)

        return output

    def disable_scs(self):
        """Put here all sc related configuration"""
        commands = [["sc", "stop", "ClickToRunSvc"], ["sc", "config", "ClickToRunSvc", "start=", "disabled"]]
        for command in commands:
            try:
                output = subprocess.check_output(command, stderr=subprocess.STDOUT)
                # log.info(output)
            except subprocess.CalledProcessError as e:
                log.error(e.output)

    def change_productid(self):
        """Randomizes Windows ProductId.
        The Windows ProductId is occasionally used by malware
        to detect public setups of Cuckoo, e.g., Malwr.com.
        """
        key = OpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_SET_VALUE)

        value = "{0}-{1}-{2}-{3}".format(random_integer(5), random_integer(3), random_integer(7), random_integer(5))

        SetValueEx(key, "ProductId", 0, REG_SZ, value)
        CloseKey(key)

    def _office_helper(self, key, subkey, value, size=REG_SZ):
        tmp_key = OpenKey(HKEY_CURRENT_USER, key, 0, KEY_SET_VALUE)
        SetValueEx(tmp_key, subkey, 0, size, value)
        CloseKey(tmp_key)

    def set_office_params(self):
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

        self._office_helper("Software\\Microsoft\\Office\\Common\\Security", "DisableAllActiveX", REG_DWORD, 0)
        self._office_helper("Software\\Microsoft\\Office\\Common\\Security", "UFIControls", REG_DWORD, 1)
        for oVersion in installedVersions:
            for software in ("Word", "Excel", "PowerPoint", "Publisher", "Outlook"):
                productPath = r"{0}\{1}\{2}".format(baseOfficeKeyPath, oVersion, software)
                self._office_helper(productPath + "\\Common\\General", "ShownOptIn", REG_DWORD, 1)
                self._office_helper(productPath + "\\Security", "VBAWarnings", REG_DWORD, 1)
                self._office_helper(productPath + "\\Security", "AccessVBOM", REG_DWORD, 1)
                self._office_helper(productPath + "\\Security", "DisableDDEServerLaunch", REG_DWORD, 0)
                self._office_helper(productPath + "\\Security", "MarkInternalAsUnsafe", REG_DWORD, 0)
                self._office_helper(productPath + "\\Security\\ProtectedView", "DisableAttachmentsInPV", REG_DWORD, 1)
                self._office_helper(productPath + "\\Security\\ProtectedView", "DisableInternetFilesInPV", REG_DWORD, 1)
                self._office_helper(productPath + "\\Security\\ProtectedView", "DisableUnsafeLocationsInPV", REG_DWORD, 1)
                # self._office_helper("HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Office\\{}\\{}\\Security".format(oVersion, software), "MarkInternalAsUnsafe", REG_DWORD, 0)
                self._office_helper(productPath + "\\Security", "ExtensionHardening", 0)

    def set_office_mrus(self):
        """Adds randomized MRU's to Office software(s).
        Occasionally used by macros to detect sandbox environments.
        """
        baseOfficeKeyPath = r"Software\Microsoft\Office"
        installedVersions = list()
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
            for software in extensions:
                values = list()
                mruKeyPath = ""
                productPath = r"{0}\{1}\{2}".format(baseOfficeKeyPath, oVersion, software)
                try:
                    productKey = OpenKey(HKEY_CURRENT_USER, productPath, 0, KEY_READ)
                    CloseKey(productKey)
                    mruKeyPath = r"{0}\File MRU".format(productPath)
                    try:
                        mruKey = OpenKey(HKEY_CURRENT_USER, mruKeyPath, 0, KEY_READ)
                    except WindowsError:
                        mruKey = CreateKeyEx(HKEY_CURRENT_USER, mruKeyPath, 0, KEY_READ)
                    displayValue = False
                    for mruKeyInfo in range(0, QueryInfoKey(mruKey)[1]):
                        currentValue = EnumValue(mruKey, mruKeyInfo)
                        if currentValue[0] == "Max Display":
                            displayValue = True
                        values.append(currentValue)
                    CloseKey(mruKey)
                except WindowsError:
                    # An Office version was found in the registry but the
                    # software (Word/Excel/PowerPoint) was not installed.
                    values = "notinstalled"

                if values != "notinstalled" and len(values) < 5:
                    mruKey = OpenKey(HKEY_CURRENT_USER, mruKeyPath, 0, KEY_SET_VALUE)
                    if not displayValue:
                        SetValueEx(mruKey, "Max Display", 0, REG_DWORD, 25)

                    for i in range(1, randint(10, 30)):
                        rString = random_string(minimum=11, charset="0123456789ABCDEF")
                        if i % 2:
                            baseId = "T01D1C" + rString
                        else:
                            baseId = "T01D1D" + rString
                        setVal = "[F00000000][{0}][O00000000]*{1}{2}.{3}".format(
                            baseId,
                            basePaths[randint(0, len(basePaths) - 1)],
                            random_string(minimum=3, maximum=15, charset="abcdefghijkLMNOPQURSTUVwxyz_0369"),
                            extensions[software][randint(0, len(extensions[software]) - 1)],
                        )
                        name = "Item {0}".format(i)
                        SetValueEx(mruKey, name, 0, REG_SZ, setVal)
                    CloseKey(mruKey)

    def ramnit(self):
        key = OpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_SET_VALUE)

        SetValueEx(key, "jfghdug_ooetvtgk", 0, REG_SZ, "TRUE")
        CloseKey(key)

    """
    def netbios(self):
        try:
            # get netbios interface
            for path in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
                netbios_init = "System\\{}\\Services\\NetBT\\Parameters\\Interfaces\\".format(path)
                netbios = OpenKey(HKEY_LOCAL_MACHINE, netbios_init,0, KEY_READ)
                for currentKey in xrange(0, QueryInfoKey(netbios)[0]):
                    subkey = EnumKey(netbios, currentKey)
                    if  subkey.startswith("Tcpip_"):
                        sub_netbios = OpenKey(HKEY_LOCAL_MACHINE, netbios_init+"\\"+subkey, 0, KEY_SET_VALUE)
                        SetValueEx(sub_netbios, "NetbiosOptions", 0, REG_DWORD, 2)
                        CloseKey(sub_netbios)
                CloseKey(netbios)

            # disable lmhosts
            lmhosts = OpenKey(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\NetBT\\Parameters\\", 0, KEY_SET_VALUE)
            SetValueEx(lmhosts, "EnableLMHOSTS", 0, REG_DWORD, 0)
            CloseKey(sub_netbios)

        except Exception as e:
            print(e)
    """

    def replace_reg_strings(self, regkey):
        regcmd = "C:\\Windows\\System32\\reg.exe"
        filepath = os.path.join("C:\\Windows\\Temp", regkey.rstrip("\\").split("\\")[-1] + ".reg")

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

        log.info("Disguising GUID to " + str(createdUUID))
        keyPath = "SOFTWARE\\Microsoft\\Cryptography"

        # Determing if the machine is 32 or 64 bit and open the registry key
        if platform.machine().endswith('64'):
            key = OpenKey(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE | KEY_WOW64_64KEY)
        else:
            key = OpenKey(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE)

        # Replace the UUID with the new UUID
        SetValueEx(key, "MachineGuid", 0, REG_SZ, createdUUID)
        CloseKey(key)

    def start(self):
        self.change_productid()
        self.set_office_mrus()
        self.ramnit()
        self.randomizeUUID()
        # self.disable_scs()
        # self.netbios()
        # self.replace_reg_strings('HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE')
        # self.replace_reg_strings('HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI')
        return True
