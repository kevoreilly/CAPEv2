# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# https://github.com/cuckoosandbox/cuckoo/blob/master/cuckoo/core/guest.py
from __future__ import absolute_import
import os
import sys
import json
import time
import socket
import logging
import datetime
import requests

from io import BytesIO
from zipfile import ZipFile, ZIP_STORED

from lib.cuckoo.common.config import Config, parse_options
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT, CUCKOO_GUEST_INIT
from lib.cuckoo.common.constants import CUCKOO_GUEST_COMPLETED
from lib.cuckoo.common.constants import CUCKOO_GUEST_FAILED
from lib.cuckoo.common.exceptions import (
    CuckooMachineError,
    CuckooGuestError,
    CuckooOperationalError,
    CuckooMachineSnapshotError,
    CuckooCriticalError,
    CuckooGuestCriticalTimeout,
)
from lib.cuckoo.common.utils import TimeoutServer, sanitize_filename
from lib.cuckoo.core.resultserver import ResultServer
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)
db = Database()
cfg = Config()


def analyzer_zipfile(platform):
    """Create the zip file that is sent to the Guest."""
    t = time.time()

    zip_data = BytesIO()
    zip_file = ZipFile(zip_data, "w", ZIP_STORED)

    # Select the proper analyzer's folder according to the operating
    # system associated with the current machine.
    root = os.path.join(CUCKOO_ROOT, "analyzer", platform)
    root_len = len(os.path.abspath(root))

    if not os.path.exists(root):
        log.error("No valid analyzer found at path: %s", root)
        raise CuckooGuestError("No valid analyzer found for %s platform!" % platform)

    # Walk through everything inside the analyzer's folder and write
    # them to the zip archive.
    for root, dirs, files in os.walk(root):
        archive_root = os.path.abspath(root)[root_len:]
        for name in files:
            path = os.path.join(root, name)
            archive_name = os.path.join(archive_root, name)
            zip_file.write(path, archive_name)
        # ToDo remove
        """
        for name in os.listdir(dirpath):
            zip_file.write(
                os.path.join(dirpath, name), os.path.join("bin", name)
            )
        """

    zip_file.close()
    data = zip_data.getvalue()
    zip_data.close()

    if time.time() - t > 10:
        log.warning(
            "It took more than 10 seconds to build the Analyzer Zip for the "
            "Guest. This might be a serious performance penalty. Is your "
            "analyzer/windows/ directory bloated with unnecessary files?"
        )

    return data


class GuestManager(object):
    """This class represents the new Guest Manager. It operates on the new
    Cuckoo Agent which features a more abstract but more feature-rich API."""

    def __init__(self, vm_id, ip, platform, task_id, analysis_manager):
        self.vmid = vm_id
        self.ipaddr = ip
        self.port = CUCKOO_GUEST_PORT
        self.platform = platform
        self.task_id = task_id
        self.analysis_manager = analysis_manager
        self.timeout = None

        # We maintain the path of the Cuckoo Analyzer on the host.
        self.analyzer_path = None
        self.environ = {}

        self.options = {}
        self.do_run = True

    @property
    def aux(self):
        return self.analysis_manager.aux

    def stop(self):
        self.do_run = False

    def get(self, method, *args, **kwargs):
        """Simple wrapper around requests.get()."""
        do_raise = kwargs.pop("do_raise", True)
        url = "http://%s:%s%s" % (self.ipaddr, self.port, method)
        with requests.Session() as session:
            session.trust_env = False
            session.proxies = None

            try:
                r = session.get(url, *args, **kwargs)
            except requests.ConnectionError:
                raise CuckooGuestError(
                    "CAPE Agent failed without error status, please try "
                    "upgrading to the latest version of agent.py (>= 0.10) and "
                    "notify us if the issue persists."
                )

        do_raise and r.raise_for_status()
        return r

    def post(self, method, *args, **kwargs):
        """Simple wrapper around requests.post()."""
        url = "http://%s:%s%s" % (self.ipaddr, self.port, method)
        session = requests.Session()
        session.trust_env = False
        session.proxies = None

        try:
            r = session.post(url, *args, **kwargs)
        except requests.ConnectionError:
            raise CuckooGuestError(
                "CAPE Agent failed without error status, please try "
                "upgrading to the latest version of agent.py (>= 0.10) and "
                "notify us if the issue persists."
            )

        r.raise_for_status()
        return r

    def wait_available(self):
        """Wait until the Virtual Machine is available for usage."""
        end = time.time() + self.timeout

        while db.guest_get_status(self.task_id) == "starting" and self.do_run:
            try:
                socket.create_connection((self.ipaddr, self.port), 1).close()
                break
            except socket.timeout:
                log.debug("%s: not ready yet", self.vmid)
            except socket.error:
                log.debug("%s: not ready yet", self.vmid)
                time.sleep(1)

            if time.time() > end:
                raise CuckooGuestCriticalTimeout(
                    "Machine %s: the guest initialization hit the critical timeout, analysis aborted." % self.vmid
                )

    def query_environ(self):
        """Query the environment of the Agent in the Virtual Machine."""
        self.environ = self.get("/environ").json()["environ"]

    def determine_analyzer_path(self):
        """Determine the path of the analyzer. Basically creating a temporary
        directory in the systemdrive, i.e., C:\\."""
        systemdrive = self.determine_system_drive()

        options = parse_options(self.options["options"])
        if options.get("analpath"):
            dirpath = systemdrive + options["analpath"]
            r = self.post("/mkdir", data={"dirpath": dirpath})
            self.analyzer_path = dirpath
        else:
            r = self.post("/mkdtemp", data={"dirpath": systemdrive})
            self.analyzer_path = r.json()["dirpath"]

    def determine_system_drive(self):
        if self.platform == "windows":
            return "%s/" % self.environ["SYSTEMDRIVE"]
        return "/"

    def determine_temp_path(self):
        if self.platform == "windows":
            return self.environ["TEMP"]
        return "/tmp"

    def upload_analyzer(self):
        """Upload the analyzer to the Virtual Machine."""
        zip_data = analyzer_zipfile(self.platform)

        log.debug("Uploading analyzer to guest (id=%s, ip=%s, size=%d)", self.vmid, self.ipaddr, len(zip_data))

        self.determine_analyzer_path()
        data = {
            "dirpath": self.analyzer_path,
        }
        self.post("/extract", files={"zipfile": zip_data}, data=data)

    def add_config(self, options):
        """Upload the analysis.conf for this task to the Virtual Machine."""
        config = [
            "[analysis]",
        ]
        for key, value in options.items():
            # Encode datetime objects the way xmlrpc encodes them.
            if isinstance(value, datetime.datetime):
                config.append("%s = %s" % (key, value.strftime("%Y%m%dT%H:%M:%S")))
            else:
                config.append("%s = %s" % (key, value))

        data = {
            "filepath": os.path.join(self.analyzer_path, "analysis.conf"),
        }
        self.post("/store", files={"file": "\n".join(config)}, data=data)

    def upload_support_files(self, options):
        """ Upload supporting files from zip temp directory if they exist
        :param options: options
        :return:
        """
        log.info("Uploading support files to guest (id={}, ip={})".format(self.vmid, self.ipaddr))
        basedir = os.path.dirname(options["target"])

        for dirpath, _, files in os.walk(basedir):
            for xf in files:
                target = os.path.join(dirpath, xf)
                # Copy all files except for the original target
                if not target == options["target"]:
                    data = {"filepath": os.path.join(self.determine_temp_path(), xf)}
                    files = {"file": (xf, open(target, "rb"))}
                    self.post("/store", files=files, data=data)
        return

    def start_analysis(self, options):
        """Start the analysis by uploading all required files.
        @param options: the task options
        """
        log.info("Starting analysis #%s on guest (id=%s, ip=%s)", self.task_id, self.vmid, self.ipaddr)

        self.options = options
        self.timeout = options["timeout"] + cfg.timeouts.critical

        # Wait for the agent to come alive.
        self.wait_available()
        if not self.do_run:
            return

        # Could be beautified a bit, but basically we have to perform the
        # same check here as we did in wait_available().
        if db.guest_get_status(self.task_id) != "starting":
            return

        r = self.get("/", do_raise=False)

        if r.status_code != 200:
            log.critical(
                "While trying to determine the Agent version that your VM is "
                "running we retrieved an unexpected HTTP status code: %s. If "
                "this is a false positive, please report this issue to the "
                "Cuckoo Developers. HTTP response headers: %s",
                r.status_code,
                json.dumps(dict(r.headers)),
            )
            db.guest_set_status(self.task_id, "failed")
            return

        try:
            status = r.json()
            version = status.get("version")
            features = status.get("features", [])
        except:
            log.critical(
                "We were unable to detect Agent in the "
                "Guest VM, are you sure you have set it up correctly? Please "
                "go through the documentation once more and otherwise inform "
                "the Cuckoo Developers of your issue."
            )
            db.guest_set_status(self.task_id, "failed")
            return

        log.info("Guest is running CAPE Agent %s (id=%s, ip=%s)", version, self.vmid, self.ipaddr)

        # Pin the Agent to our IP address so that it is not accessible by
        # other Virtual Machines etc.
        if "pinning" in features:
            self.get("/pinning")

        # Obtain the environment variables.
        self.query_environ()

        # Upload the analyzer.
        self.upload_analyzer()

        # Pass along the analysis.conf file.
        self.add_config(options)
        # Allow Auxiliary modules to prepare the Guest.
        # ToDo fix it
        # self.aux.callback("prepare_guest")

        # If the target is a file, upload it to the guest.
        if options["category"] == "file" or options["category"] == "archive":
            data = {
                "filepath": os.path.join(self.determine_temp_path(), options["file_name"]),
            }
            files = {
                "file": ("sample.bin", open(options["target"], "rb")),
            }
            self.post("/store", files=files, data=data)

        # check for support files and upload them to guest.
        self.upload_support_files(options)

        # Debug analyzer.py in vm
        if "CAPE_DBG" in os.environ:
            while True:
                pass

        if "execpy" in features:
            data = {
                "filepath": "%s/analyzer.py" % self.analyzer_path,
                "async": "yes",
                "cwd": self.analyzer_path,
            }
            self.post("/execpy", data=data)
        else:
            # Execute the analyzer that we just uploaded.
            data = {
                "command": "%s %s\\analyzer.py" % (sys.executable, self.analyzer_path),
                "async": "yes",
                "cwd": self.analyzer_path,
            }
            self.post("/execute", data=data)

    def wait_for_completion(self):

        count = 0
        end = time.time() + self.timeout

        while db.guest_get_status(self.task_id) == "running" and self.do_run:
            if count >= 5:
                log.debug("%s: analysis #%s is still running", self.vmid, self.task_id)
                count = 0

            count += 1
            time.sleep(1)

            # If the analysis hits the critical timeout, just return straight
            # away and try to recover the analysis results from the guest.
            if time.time() > end:
                log.info("%s: end of analysis reached!", self.vmid)
                return

            try:
                status = self.get("/status", timeout=5).json()
            except CuckooGuestError:
                # this might fail due to timeouts or just temporary network
                # issues thus we don't want to abort the analysis just yet and
                # wait for things to recover
                log.warning(f"Virtual Machine: {self.vmid} /status failed. This can indicate the guest losing network connectivity")
                continue
            except Exception as e:
                log.error(f"Virtual machine: {self.vmid} /status failed. %s", e, exc_info=True)
                continue

            if status["status"] == "complete":
                log.info("%s: analysis completed successfully", self.vmid)
                db.guest_set_status(self.task_id, "complete")
                return
            elif status["status"] == "exception":
                log.warning("%s: analysis #%s caught an exception\n%s", self.vmid, self.task_id, status["description"])
                db.guest_set_status(self.task_id, "failed")
                return
