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

    # Event log channels to collect
    # Ref: https://github.com/Yamato-Security/EnableWindowsLogSettings
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
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Bits-Client/Operational",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "Microsoft-Windows-NTLM/Operational",
        "Microsoft-Windows-Security-Mitigations/KernelMode",
        "Microsoft-Windows-Security-Mitigations/UserMode",
        "Microsoft-Windows-PrintService/Admin",
        "Microsoft-Windows-PrintService/Operational",
        "Microsoft-Windows-SmbClient/Security",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-Diagnosis-Scripted/Operational",
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
    ]

    # Max log size in bytes - 100 MB is plenty for sandbox runs
    LOG_MAX_SIZE = 104857600

    # All channels get the same max size for sandbox use
    log_sizes = [
        "Security",
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell",
        "PowerShellCore/Operational",
        "System",
        "Application",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Bits-Client/Operational",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "Microsoft-Windows-NTLM/Operational",
        "Microsoft-Windows-Security-Mitigations/KernelMode",
        "Microsoft-Windows-Security-Mitigations/UserMode",
        "Microsoft-Windows-PrintService/Admin",
        "Microsoft-Windows-PrintService/Operational",
        "Microsoft-Windows-SmbClient/Security",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-Diagnosis-Scripted/Operational",
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
    ]

    # Logs that need to be explicitly enabled
    logs_to_enable = [
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    ]

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.enabled = config.evtx
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def enable_cmdline_logging(self):
        """Enable command line capture in Process Creation events (Security EID 4688)."""
        try:
            cmd = (
                r'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"'
                r' /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1'
            )
            subprocess.call(cmd, startupinfo=self.startupinfo)
        except Exception as err:
            log.error("Cannot enable command line auditing - %s", err)

    def configure_log_sizes(self):
        """Set maximum log sizes and enable disabled logs."""
        for channel in self.log_sizes:
            try:
                cmd = f'wevtutil sl "{channel}" /ms:{self.LOG_MAX_SIZE}'
                subprocess.call(cmd, startupinfo=self.startupinfo)
            except Exception as err:
                log.debug("Cannot set log size for %s - %s", channel, err)

        for channel in self.logs_to_enable:
            try:
                cmd = f'wevtutil sl "{channel}" /e:true'
                subprocess.call(cmd, startupinfo=self.startupinfo)
            except Exception as err:
                log.debug("Cannot enable log %s - %s", channel, err)

    def enable_advanced_logging(self):
        """
        Enable Windows advanced audit features using subcategory GUIDs.
        GUIDs work on any OS language unlike subcategory names.
        Ref: https://github.com/Yamato-Security/EnableWindowsLogSettings
        """
        # Format: (GUID, description, success, failure)
        advanced_audit_policies = [
            # Account Logon
            ("{0CCE923F-69AE-11D9-BED3-505054503030}", "Credential Validation", "enable", "enable"),
            ("{0CCE9242-69AE-11D9-BED3-505054503030}", "Kerberos Authentication Service", "enable", "enable"),
            ("{0CCE9240-69AE-11D9-BED3-505054503030}", "Kerberos Service Ticket Operations", "enable", "enable"),
            # Account Management
            ("{0CCE9236-69AE-11D9-BED3-505054503030}", "Computer Account Management", "enable", "enable"),
            ("{0CCE923A-69AE-11D9-BED3-505054503030}", "Other Account Management Events", "enable", "enable"),
            ("{0CCE9237-69AE-11D9-BED3-505054503030}", "Security Group Management", "enable", "enable"),
            ("{0CCE9235-69AE-11D9-BED3-505054503030}", "User Account Management", "enable", "enable"),
            # Detailed Tracking
            ("{0cce9248-69ae-11d9-bed3-505054503030}", "Plug and Play", "enable", "enable"),
            ("{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation", "enable", "enable"),
            ("{0CCE922E-69AE-11D9-BED3-505054503030}", "RPC Events", "enable", "enable"),
            # DS Access
            ("{0CCE923B-69AE-11D9-BED3-505054503030}", "Directory Service Access", "enable", "enable"),
            ("{0CCE923C-69AE-11D9-BED3-505054503030}", "Directory Service Changes", "enable", "enable"),
            # Logon/Logoff
            ("{0CCE9217-69AE-11D9-BED3-505054503030}", "Account Lockout", "enable", "enable"),
            ("{0CCE9216-69AE-11D9-BED3-505054503030}", "Logoff", "enable", "enable"),
            ("{0CCE9215-69AE-11D9-BED3-505054503030}", "Logon", "enable", "enable"),
            ("{0CCE921C-69AE-11D9-BED3-505054503030}", "Other Logon/Logoff Events", "enable", "enable"),
            ("{0CCE921B-69AE-11D9-BED3-505054503030}", "Special Logon", "enable", "enable"),
            # Object Access
            ("{0CCE9221-69AE-11D9-BED3-505054503030}", "Certification Services", "enable", "enable"),
            ("{0CCE9224-69AE-11D9-BED3-505054503030}", "File Share", "enable", "enable"),
            ("{0CCE9226-69AE-11D9-BED3-505054503030}", "Filtering Platform Connection", "enable", "enable"),
            ("{0CCE9227-69AE-11D9-BED3-505054503030}", "Other Object Access Events", "enable", "enable"),
            ("{0CCE9245-69AE-11D9-BED3-505054503030}", "Removable Storage", "enable", "enable"),
            ("{0CCE9220-69AE-11D9-BED3-505054503030}", "SAM", "enable", "enable"),
            # Policy Change
            ("{0CCE922F-69AE-11D9-BED3-505054503030}", "Audit Policy Change", "enable", "enable"),
            ("{0CCE9230-69AE-11D9-BED3-505054503030}", "Authentication Policy Change", "enable", "enable"),
            ("{0CCE9234-69AE-11D9-BED3-505054503030}", "Other Policy Change Events", "enable", "enable"),
            # Privilege Use
            ("{0CCE9228-69AE-11D9-BED3-505054503030}", "Sensitive Privilege Use", "enable", "enable"),
            # System
            ("{0CCE9214-69AE-11D9-BED3-505054503030}", "Other System Events", "disable", "enable"),
            ("{0CCE9210-69AE-11D9-BED3-505054503030}", "Security State Change", "enable", "enable"),
            ("{0CCE9211-69AE-11D9-BED3-505054503030}", "Security System Extension", "enable", "enable"),
            ("{0CCE9212-69AE-11D9-BED3-505054503030}", "System Integrity", "enable", "enable"),
        ]
        for guid, description, success, failure in advanced_audit_policies:
            try:
                cmd = f"auditpol /set /subcategory:{guid} /success:{success} /failure:{failure}"
                log.debug("Enabling audit policy: %s -> %s", description, cmd)
                subprocess.call(cmd, startupinfo=self.startupinfo)
            except Exception as err:
                log.error("Cannot enable audit policy %s (%s) - %s", description, guid, err)

    def collect_windows_logs(self):
        """Collect selected evtx files, as specified in self.windows_logs."""
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
        """Wipe sequentially Windows logs."""
        try:
            for evtx_channel in self.windows_logs:
                cmd = f'wevtutil cl "{evtx_channel}"'
                log.debug("Wiping %s", evtx_channel)
                subprocess.call(cmd, startupinfo=self.startupinfo)
        except Exception as err:
            log.error("Module error - %s", err)

    def run(self):
        if self.enabled:
            self.enable_cmdline_logging()
            self.configure_log_sizes()
            self.enable_advanced_logging()
            self.wipe_windows_logs()
            return True
        return False

    def stop(self):
        if self.enabled:
            self.collect_windows_logs()
        return True
