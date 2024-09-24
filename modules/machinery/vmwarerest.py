import logging
import os

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

log = logging.getLogger(__name__)

s = requests.Session()
s.verify = False


class VMwareREST(Machinery):
    """Virtualization layer for remote VMware REST Server."""

    module_name = "vmwarerest"

    LABEL = "id"

    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """
        if not self.options.vmwarerest.host:
            raise CuckooMachineError("VMwareREST hostname/IP address missing, please add it to vmwarerest.conf")
        self.host = self.options.vmwarerest.host
        if not self.options.vmwarerest.port:
            raise CuckooMachineError("VMwareREST server port address missing, please add it to vmwarerest.conf")
        self.port = str(self.options.vmwarerest.port)

        if self.options.vmwarerest.enable_tls:
            self.api_url = f"https://{self.host}:{self.port}/api"
        else:
            self.api_url = f"http://{self.host}:{self.port}/api"

        if not self.options.vmwarerest.username:
            raise CuckooMachineError("VMwareREST username missing, please add it to vmwarerest.conf")
        self.username = self.options.vmwarerest.username
        if not self.options.vmwarerest.password:
            raise CuckooMachineError("VMwareREST password missing, please add it to vmwarerest.conf")
        self.password = self.options.vmwarerest.password

        super(VMwareREST, self)._initialize_check()

        log.info("VMwareREST machinery module initialised (%s:%s)", self.host, self.port)

    def check_response(self, response):
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            raise CuckooMachineError("VMwareREST: Invalid parameters")
        elif response.status_code == 401:
            raise CuckooMachineError("VMwareREST: Authentication failed, please check credentials in vmwarerest.conf")
        elif response.status_code == 403:
            raise CuckooMachineError("VMwareREST: Permission denied")
        elif response.status_code == 404:
            raise CuckooMachineError("VMwareREST: No such resource")
        elif response.status_code == 406:
            raise CuckooMachineError("VMwareREST: Content type was not supported")
        elif response.status_code == 409:
            raise CuckooMachineError("VMwareREST: Resource state conflicts")
        elif response.status_code == 500:
            raise CuckooMachineError("VMwareREST: Server error")
        else:
            raise CuckooMachineError("VMwareREST: Unexpected error")

    def get_vms(self):
        """Returns a list of VM IDs and paths for all VMs."""
        try:
            response = s.get(
                f"{self.api_url}/vms",
                auth=(self.username, self.password),
                headers={"Accept": "application/vnd.vmware.vmw.rest-v1+json"},
            )
        except Exception:
            raise CuckooMachineError("VMwareREST: Couldn't connect to vmrest server.")

        return self.check_response(response)

    def get_power(self, vmmoid):
        """Returns the power state of the VM."""
        try:
            response = s.get(
                f"{self.api_url}/vms/{vmmoid}/power",
                auth=(self.username, self.password),
                headers={"Accept": "application/vnd.vmware.vmw.rest-v1+json"},
            )
        except Exception:
            raise CuckooMachineError("VMwareREST: Couldn't connect to vmrest server.")

        return self.check_response(response)

    def change_power_state(self, vmmoid, operation):
        """Changes the VM power state."""
        try:
            response = s.put(
                f"{self.api_url}/vms/{vmmoid}/power",
                auth=(self.username, self.password),
                data=operation,
                headers={
                    "Content-Type": "application/vnd.vmware.vmw.rest-v1+json",
                    "Accept": "application/vnd.vmware.vmw.rest-v1+json",
                },
            )
        except Exception:
            raise CuckooMachineError("VMwareREST: Couldn't connect to vmrest server.")

        return self.check_response(response)

    def get_vmmoid(self, id):
        vms = self.get_vms()
        if vms:
            for vm in vms:
                vmx_filename = os.path.basename(vm["path"].replace("\\", os.sep))
                if vmx_filename == f"{id}.vmx":
                    return vm["id"]
        raise CuckooMachineError("There was a problem getting vmmoid for vm %s", id)

    def poweron_vm(self, id):
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            log.info("Powering on vm %s", id)
            return self.change_power_state(vmmoid, "on")
        raise CuckooMachineError("There was a problem powering on vm %s", id)

    def poweroff_vm(self, id):
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            log.info("Powering off vm %s", id)
            return self.change_power_state(vmmoid, "off")
        raise CuckooMachineError("There was a problem powering off vm %s", id)

    def get_power_for_vm(self, id):
        vmmoid = self.get_vmmoid(id)
        if vmmoid:
            return self.get_power(vmmoid)
        raise CuckooMachineError("There was a problem querying power status for vm %s", id)

    def start(self, id):
        log.info("Starting vm %s", id)
        self.stop(id)
        self.poweron_vm(id)

    def stop(self, id):
        if self._is_running(id):
            log.info("Stopping vm %s", id)
            self.poweroff_vm(id)

    def _is_running(self, id):
        log.info("Checking vm %s", id)
        power_state = self.get_power_for_vm(id)

        if power_state["power_state"] == "poweredOn":
            log.info("Vm %s is running", id)
            return True
        else:
            log.info("Vm %s is not running", id)
            return False
