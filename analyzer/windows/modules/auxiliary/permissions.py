import logging
from subprocess import STARTF_USESHOWWINDOW, STARTUPINFO, call
from threading import Thread

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

__author__ = "[Canadian Centre for Cyber Security] @CybercentreCanada"


class Permissions(Auxiliary):
    """
    Change permissions for injected directory and Python interpreter
    to prevent malware from messing with analysis
    """

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.permissions
        self.startupinfo = STARTUPINFO()
        self.startupinfo.dwFlags |= STARTF_USESHOWWINDOW

    def start(self):
        if not self.enabled:
            return False

        # Put locations here that you want to protect. Do NOT put Path.cwd() or "C:\\tmp*" in the locations list,
        # as this will crash CAPE. Try to cherry-pick directories that are important to your analysis.
        # The locations must be pipe-separated. The default for CAPE is to separate items passed via options
        # with a colon, but that does not work with file paths, so | it is!
        locations = self.options.get("permissions", "")
        locations = locations.split("|")

        log.debug("Adjusting permissions for %s", locations)
        for location in locations:

            # First add a non-inherited permission for Admin Read+Execute
            # icacls <location> /grant:r "BUILTIN\Administrators:(OI)(CI)(RX)" "BUILTIN\\Administrators:(RX)" /t /c /q
            modify_admin_params = [
                "icacls",
                location,
                "/grant:r",
                "BUILTIN\\Administrators:(OI)(CI)(RX)",
                "BUILTIN\\Administrators:(RX)",
                "/t",
                "/c",
                "/q",
            ]
            t1 = Thread(target=call, args=(modify_admin_params,), kwargs={"startupinfo": self.startupinfo})
            t1.start()
            t1.join(timeout=15)
            if t1.is_alive():
                log.warning("'Modify admin' call was unable to complete in 15 seconds")

            # Then remove all inherited permissions so that only SYSTEM has Write access
            # icacls <location> /inheritancelevel:r /t /c /q
            inheritance_params = ["icacls", location, "/inheritancelevel:r", "/t", "/c", "/q"]
            t2 = Thread(target=call, args=(inheritance_params,), kwargs={"startupinfo": self.startupinfo})
            t2.start()
            t2.join(timeout=15)
            if t2.is_alive():
                log.warning("'Inheritance' call was unable to complete in 15 seconds")
