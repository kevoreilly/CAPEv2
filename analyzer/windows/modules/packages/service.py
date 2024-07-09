# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging
import sys

from lib.api.process import Process
from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS, OPT_SERVICEDESC, OPT_SERVICENAME
from lib.common.defines import ADVAPI32, KERNEL32

INJECT_CREATEREMOTETHREAD = 0
INJECT_QUEUEUSERAPC = 1
SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SC_MANAGER_LOCK = 0x0008
SC_MANAGER_QUERY_LOCK_STATUS = 0x0010
SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020
SC_MANAGER_ALL_ACCESS = (
    SC_MANAGER_CONNECT
    | SC_MANAGER_CREATE_SERVICE
    | SC_MANAGER_ENUMERATE_SERVICE
    | SC_MANAGER_LOCK
    | SC_MANAGER_QUERY_LOCK_STATUS
    | SC_MANAGER_MODIFY_BOOT_CONFIG
)
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_PAUSE_CONTINUE = 0x0040
SERVICE_INTERROGATE = 0x0080
SERVICE_USER_DEFINED_CONTROL = 0x0100
SERVICE_ALL_ACCESS = (
    SERVICE_QUERY_CONFIG
    | SERVICE_CHANGE_CONFIG
    | SERVICE_QUERY_STATUS
    | SERVICE_ENUMERATE_DEPENDENTS
    | SERVICE_START
    | SERVICE_STOP
    | SERVICE_PAUSE_CONTINUE
    | SERVICE_INTERROGATE
    | SERVICE_USER_DEFINED_CONTROL
)
SERVICE_WIN32_OWN_PROCESS = 0x0010
SERVICE_INTERACTIVE_PROCESS = 0x0100
SERVICE_DEMAND_START = 0x0003
SERVICE_ERROR_IGNORE = 0x0000
log = logging.getLogger(__name__)

SERVICE_OPTIONS = (OPT_SERVICENAME, OPT_SERVICEDESC, OPT_ARGUMENTS)


class Service(Package):
    """Service analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "sc.exe"),
    ]
    summary = "Launch the given sample as a service."
    description = """Use 'svchost.exe -k capegroup <sample> [arguments]' to launch the sample
    as a service.
    The .exe filename extension will be added automatically."""
    option_names = SERVICE_OPTIONS

    def start(self, path):
        try:
            servicename = self.options.get(OPT_SERVICENAME, "CAPEService").encode("utf8")
            servicedesc = self.options.get(OPT_SERVICEDESC, "CAPE Service").encode("utf8")
            arguments = self.options.get(OPT_ARGUMENTS)
            path = check_file_extension(path, ".exe")
            binpath = f'"{path}"'.encode("utf8")
            if arguments:
                binpath += f" {arguments}"
            scm_handle = ADVAPI32.OpenSCManagerA(None, None, SC_MANAGER_ALL_ACCESS)
            if scm_handle == 0:
                log.info("Failed to open SCManager")
                log.info(ctypes.FormatError())
                return
            service_handle = ADVAPI32.CreateServiceA(
                scm_handle,
                servicename,
                servicedesc,
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                binpath,
                None,
                None,
                None,
                None,
                None,
            )
            if service_handle == 0:
                log.info("Failed to create service")
                log.info(ctypes.FormatError())
                return
            log.info("Created service (handle: 0x%s)", service_handle)
            servproc = Process(options=self.options, config=self.config, pid=self.config.services_pid)
            filepath = servproc.get_filepath()
            servproc.inject(interest=filepath, nosleepskip=True)
            servproc.close()
            KERNEL32.Sleep(500)
            service_launched = ADVAPI32.StartServiceA(service_handle, 0, None)
            if service_launched:
                log.info("Successfully started service")
            else:
                log.info(ctypes.FormatError())
                log.info("Failed to start service")
            ADVAPI32.CloseServiceHandle(service_handle)
            ADVAPI32.CloseServiceHandle(scm_handle)
            return
        except Exception as e:
            log.info(sys.exc_info()[0])
            log.info(e)
            log.info(e.__dict__)
            log.info(e.__class__)
            log.exception(e)
