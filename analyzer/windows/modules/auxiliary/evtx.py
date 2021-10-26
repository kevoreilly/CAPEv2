from __future__ import absolute_import
from threading import Thread
import logging
import zipfile
import os

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host
from lib.core.config import Config

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

    def __init__(self, options={}, config=None):
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")
        self.enabled = self.config.evtx
        self.do_run = self.enabled

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
                        f'auditpol /set /subcategory:"{subcategory}"'
                        f'/success:{settings["success"]} /failure:{settings["failure"]}'
                    )
                    log.debug(f"Enabling advanced logging -> {cmd}")
                    os.system(cmd)
                except Exception as err:
                    log.error(
                        f"Cannot enable advanced logging for subcategory {subcategory} - {err}"
                    )
                    pass

    def collect_windows_logs(self):
        """
        Collect selected evtx files, as specified in self.windows_logs
        """

        logs_folder = None
        try:
            logs_folder = "C:/windows/Sysnative/winevt/Logs"
            os.listdir(logs_folder)
        except:
            logs_folder = "c:/Windows/System32/winevt/Logs"

        with zipfile.ZipFile(self.evtx_dump, "w", zipfile.ZIP_DEFLATED) as zip_obj:
            for evtx_file_name in os.listdir(logs_folder):
                for selected_evtx in self.windows_logs:
                    _selected_evtx = selected_evtx + ".evtx"
                    if "/" in _selected_evtx:
                        _selected_evtx = "%4".join(_selected_evtx.split("/"))
                    if _selected_evtx == evtx_file_name:
                        full_path = os.path.join(logs_folder, evtx_file_name)
                        if os.path.exists(full_path):
                            log.debug(f"Adding {full_path} to zip dump")
                            zip_obj.write(full_path, evtx_file_name)

        log.debug(f"Uploading {self.evtx_dump} to host")
        upload_to_host(self.evtx_dump, f"evtx/{self.evtx_dump}", False)

    def wipe_windows_logs(self):
        """
        Wipe sequentially Windows logs
        """
        try:
            for evtx_channel in self.windows_logs:
                cmd = f"wevtutil cl {evtx_channel}"
                log.debug(f"wiping {evtx_channel}")
                os.system(cmd)
        except Exception as err:
            log.error(f"module error - {err}")
            pass

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
        return False
