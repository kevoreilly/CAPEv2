import itertools
import logging
import os
import subprocess
import zipfile
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)


class Evtx(Thread, Auxiliary):

    evtx_dump = "evtx.zip"

    windows_logs = [
        "Application",
        "HardwareEvents",
        "Internet Explorer",
        "Key Management Service",
        "OAlerts",
        "Security",
        "Setup",
        "System",
        "Windows PowerShell",
        "Microsoft-Windows-Sysmon/Operational",
    ]

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.enabled = config.evtx
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def enable_advanced_logging(self):
        """
        Enable Windows advanced audit features
            ref: https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=RecBaselineAudPol
        """
        advanced_audit_policies = [
            {"Security State Change": {"success": "enable", "failure": "enable"}},
            {"Security System Extension": {"success": "enable", "failure": "enable"}},
            {"System Integrity": {"success": "enable", "failure": "enable"}},
            {"IPsec Driver": {"success": "disable", "failure": "disable"}},
            {"Other System Events": {"success": "disable", "failure": "enable"}},
            {"Logon": {"success": "enable", "failure": "enable"}},
            {"Logoff": {"success": "enable", "failure": "enable"}},
            {"Account Lockout": {"success": "enable", "failure": "enable"}},
            {"IPsec Main Mode": {"success": "disable", "failure": "disable"}},
            {"IPsec Quick Mode": {"success": "disable", "failure": "disable"}},
            {"IPsec Extended Mode": {"success": "disable", "failure": "disable"}},
            {"Other Logon/Logoff Events": {"success": "enable", "failure": "enable"}},
            {"Network Policy Server": {"success": "enable", "failure": "enable"}},
            {"Special Logon": {"success": "enable", "failure": "enable"}},
            {"File System": {"success": "enable", "failure": "enable"}},
            {"Registry": {"success": "enable", "failure": "enable"}},
            {"Kernel Object": {"success": "enable", "failure": "enable"}},
            {"SAM": {"success": "disable", "failure": "disable"}},
            {"Certification Services": {"success": "enable", "failure": "enable"}},
            {"Handle Manipulation": {"success": "disable", "failure": "disable"}},
            {"Application Generated": {"success": "enable", "failure": "enable"}},
            {"File Share": {"success": "enable", "failure": "enable"}},
            {
                "Filtering Platform Packet Drop": {
                    "success": "disable",
                    "failure": "disable",
                }
            },
            {
                "Filtering Platform Connection": {
                    "success": "disable",
                    "failure": "disable",
                }
            },
            {
                "Other Object Access Events": {
                    "success": "disable",
                    "failure": "disable",
                }
            },
            {"Sensitive Privilege Use": {"success": "disable", "failure": "disable"}},
            {
                "Non Sensitive Privilege Use": {
                    "success": "disable",
                    "failure": "disable",
                }
            },
            {
                "Other Privilege Use Events": {
                    "success": "disable",
                    "failure": "disable",
                }
            },
            {"RPC Events": {"success": "enable", "failure": "enable"}},
            {"Audit Policy Change": {"success": "enable", "failure": "enable"}},
            {
                "Authentication Policy Change": {
                    "success": "enable",
                    "failure": "enable",
                }
            },
            {
                "MPSSVC Rule-Level Policy Change": {
                    "success": "disable",
                    "failure": "disable",
                }
            },
            {
                "Filtering Platform Policy Change": {
                    "success": "disable",
                    "failure": "disable",
                }
            },
            {"Other Policy Change Events": {"success": "disable", "failure": "enable"}},
            {"User Account Management": {"success": "enable", "failure": "enable"}},
            {"Computer Account Management": {"success": "enable", "failure": "enable"}},
            {"Security Group Management": {"success": "enable", "failure": "enable"}},
            {
                "Distribution Group Management": {
                    "success": "enable",
                    "failure": "enable",
                }
            },
            {
                "Application Group Management": {
                    "success": "enable",
                    "failure": "enable",
                }
            },
            {
                "Other Account Management Events": {
                    "success": "enable",
                    "failure": "enable",
                }
            },
            {"Directory Service Access": {"success": "enable", "failure": "enable"}},
            {"Directory Service Changes": {"success": "enable", "failure": "enable"}},
            {
                "Directory Service Replication": {
                    "success": "disable",
                    "failure": "enable",
                }
            },
            {
                "Detailed Directory Service Replication": {
                    "success": "disable",
                    "failure": "disable",
                }
            },
            {"Credential Validation": {"success": "enable", "failure": "enable"}},
            {
                "Kerberos Service Ticket Operations": {
                    "success": "enable",
                    "failure": "enable",
                }
            },
            {"Other Account Logon Events": {"success": "enable", "failure": "enable"}},
            {
                "Kerberos Authentication Service": {
                    "success": "enable",
                    "failure": "enable",
                }
            },
        ]
        for policy in advanced_audit_policies:
            for subcategory, settings in policy.items():
                try:
                    cmd = (
                        f'auditpol /set /subcategory:"{subcategory}" /success:{settings["success"]} /failure:{settings["failure"]}'
                    )
                    log.debug("Enabling advanced logging -> %s", cmd)
                    subprocess.call(
                        cmd,
                        startupinfo=self.startupinfo,
                    )
                except Exception as err:
                    log.error("Cannot enable advanced logging for subcategory %s - %s", subcategory, err)

    def collect_windows_logs(self):
        """
        Collect selected evtx files, as specified in self.windows_logs
        """

        logs_folder = None
        try:
            logs_folder = "C:/windows/Sysnative/winevt/Logs"
            os.listdir(logs_folder)
        except Exception:
            logs_folder = "C:/Windows/System32/winevt/Logs"

        with zipfile.ZipFile(self.evtx_dump, "w", zipfile.ZIP_DEFLATED) as zip_obj:
            for evtx_file_name, selected_evtx in itertools.product(os.listdir(logs_folder), self.windows_logs):
                _selected_evtx = f"{selected_evtx}.evtx"
                _selected_evtx = _selected_evtx.replace("/", "%4")
                if _selected_evtx == evtx_file_name:
                    full_path = os.path.join(logs_folder, evtx_file_name)
                    if os.path.exists(full_path):
                        log.debug("Adding %s to zip dump", full_path)
                        zip_obj.write(full_path, evtx_file_name)

        log.debug("Uploading %s to host", self.evtx_dump)
        upload_to_host(self.evtx_dump, f"evtx/{self.evtx_dump}")

    def wipe_windows_logs(self):
        """
        Wipe sequentially Windows logs
        """
        try:
            for evtx_channel in self.windows_logs:
                cmd = f"wevtutil cl {evtx_channel}"
                log.debug("Wiping %s", evtx_channel)
                subprocess.call(
                    cmd,
                    startupinfo=self.startupinfo,
                )
        except Exception as err:
            log.error("Module error - %s", err)

    def run(self):
        if self.enabled:
            self.enable_advanced_logging()
            self.wipe_windows_logs()
            return True
        return False

    def stop(self):
        if self.enabled:
            self.collect_windows_logs()
        return True
