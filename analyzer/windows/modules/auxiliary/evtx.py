import logging
import os
import subprocess
import time
import zipfile
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)


class Evtx(Thread, Auxiliary):
    # Stop AFTER capemon-related auxiliaries so the final EVTX snapshot
    # captures sysmon events from late-fire callbacks that fire between
    # the analysis-stopping signal and the VM teardown (e.g. C2 callbacks
    # the malware schedules after a delay). Without this priority bump,
    # those events happen after the last EVTX snapshot and never reach
    # the host-side processing modules.
    start_priority = 0
    stop_priority = -20

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

    # Interval in seconds between periodic snapshots
    SNAPSHOT_INTERVAL = 30

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.enabled = config.evtx
        self.do_run = True
        self.snapshot_count = 0
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

    def export_windows_logs(self, output_zip):
        """Export event logs using wevtutil epl (proper export, flushes buffers).

        Unlike raw file copy, wevtutil epl ensures all buffered events are
        written and the exported file is a consistent snapshot.

        """
        export_dir = os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), "evtx_export")
        os.makedirs(export_dir, exist_ok=True)

        exported = []
        for channel in self.windows_logs:
            safe_name = channel.replace("/", "%4") + ".evtx"
            export_path = os.path.join(export_dir, safe_name)
            try:
                # Remove previous export if exists
                if os.path.exists(export_path):
                    os.unlink(export_path)
                cmd = f'wevtutil epl "{channel}" "{export_path}" /ow:true'
                result = subprocess.call(cmd, startupinfo=self.startupinfo,
                                         timeout=30)
                if result == 0 and os.path.exists(export_path):
                    size = os.path.getsize(export_path)
                    if size > 0:
                        exported.append((export_path, safe_name))
            except subprocess.TimeoutExpired:
                log.debug("Timeout exporting %s", channel)
            except Exception as err:
                log.debug("Cannot export %s - %s", channel, err)

        if not exported:
            return

        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zip_obj:
            for export_path, safe_name in exported:
                try:
                    zip_obj.write(export_path, safe_name)
                except Exception as err:
                    log.debug("Cannot add %s to zip - %s", safe_name, err)

        # Clean up exported files
        for export_path, _ in exported:
            try:
                os.unlink(export_path)
            except Exception:
                pass
        try:
            os.rmdir(export_dir)
        except Exception:
            pass

    def wipe_windows_logs(self):
        """Wipe sequentially Windows logs."""
        try:
            for evtx_channel in self.windows_logs:
                cmd = f'wevtutil cl "{evtx_channel}"'
                log.debug("Wiping %s", evtx_channel)
                subprocess.call(cmd, startupinfo=self.startupinfo)
        except Exception as err:
            log.error("Module error - %s", err)

    def take_snapshot(self):
        """Export current logs to a local snapshot dir, then wipe.

        Snapshots are kept locally on the guest and merged into a single
        evtx.zip at stop() time. This protects against malware clearing
        logs — each snapshot captures events since the last wipe.
        """
        self.snapshot_count += 1
        snapshot_dir = os.path.join(
            os.environ.get("TEMP", "C:\\Windows\\Temp"),
            "evtx_snapshots",
            str(self.snapshot_count),
        )
        os.makedirs(snapshot_dir, exist_ok=True)

        try:
            for channel in self.windows_logs:
                safe_name = channel.replace("/", "%4") + ".evtx"
                export_path = os.path.join(snapshot_dir, safe_name)
                try:
                    cmd = f'wevtutil epl "{channel}" "{export_path}" /ow:true'
                    subprocess.call(cmd, startupinfo=self.startupinfo, timeout=30)
                except Exception:
                    pass

            self.wipe_windows_logs()
            log.debug("Took evtx snapshot %d", self.snapshot_count)
        except Exception as err:
            log.error("Failed to take evtx snapshot - %s", err)

    def run(self):
        if not self.enabled:
            return False

        self.enable_cmdline_logging()
        self.configure_log_sizes()
        self.enable_advanced_logging()
        self.wipe_windows_logs()

        # Periodic snapshot loop — captures events even if malware wipes logs
        while self.do_run:
            for _ in range(self.SNAPSHOT_INTERVAL):
                if not self.do_run:
                    break
                time.sleep(1)
            if self.do_run:
                self.take_snapshot()

        return True

    def stop(self):
        self.do_run = False
        if not self.enabled:
            return True

        # Take final snapshot of remaining events
        self.take_snapshot()

        # Merge all snapshots into a single evtx.zip.
        # Each snapshot is incremental (logs wiped after each), so we
        # include ALL snapshots. Since evtx files can't be concatenated,
        # we add each snapshot's evtx with a unique name (channel_N.evtx).
        snapshot_base = os.path.join(
            os.environ.get("TEMP", "C:\\Windows\\Temp"),
            "evtx_snapshots",
        )

        with zipfile.ZipFile(self.evtx_dump, "w", zipfile.ZIP_DEFLATED) as zip_obj:
            if os.path.isdir(snapshot_base):
                for snap_name in sorted(os.listdir(snapshot_base), key=lambda x: int(x) if x.isdigit() else x):
                    snap_dir = os.path.join(snapshot_base, snap_name)
                    if not os.path.isdir(snap_dir):
                        continue
                    for evtx_file in os.listdir(snap_dir):
                        if not evtx_file.lower().endswith(".evtx"):
                            continue
                        full_path = os.path.join(snap_dir, evtx_file)
                        if os.path.getsize(full_path) == 0:
                            continue
                        # Add with snapshot number prefix to avoid name collisions
                        arc_name = f"{snap_name}_{evtx_file}"
                        try:
                            zip_obj.write(full_path, arc_name)
                        except Exception:
                            pass

        if os.path.exists(self.evtx_dump):
            upload_to_host(self.evtx_dump, f"evtx/{self.evtx_dump}")

        # Clean up
        try:
            import shutil
            shutil.rmtree(snapshot_base, ignore_errors=True)
        except Exception:
            pass

        return True
