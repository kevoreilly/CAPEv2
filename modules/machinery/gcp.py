import logging

from lib.cuckoo.common.config import Config
from typing import List

cfg = Config()
HAVE_GCP = False
if cfg.cuckoo.machinery == "gcp":
    try:
        from google.cloud import compute_v1
        from google.oauth2 import service_account
        from google.auth import compute_engine

        HAVE_GCP = True
    except ImportError:
        pass

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooDependencyError

log = logging.getLogger(__name__)


class GCP(Machinery):

    module_name = "gcp"

    # VM states
    RUNNING = "RUNNING"
    PAUSED = "SUSPENDED"
    POWEROFF = "TERMINATED"
    PENDING = "PENDING"
    ABORTED = "ABORTED"
    ERROR = "ERROR"

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooDependencyError: if google-cloud-compute is not installed
        @raise CuckooMachineError: if configuration is invalid
        """
        if not HAVE_GCP:
            raise CuckooDependencyError("Missed google-cloud-compute dependencies: poetry add google-cloud-compute")

        # Read Configuration
        self.project = self.options.gcp.project
        self.zone = self.options.gcp.zone
        self.json_key_path = getattr(self.options.gcp, "service_account_path", None)
        self.running_in_gcp = getattr(self.options.gcp, "running_in_gcp", False)

        log.info("Connecting to GCP Project: %s, Zone: %s", self.project, self.zone)

        # Initialize Clients
        if self.json_key_path:
            creds = service_account.Credentials.from_service_account_file(self.json_key_path)
            self.instances_client = compute_v1.InstancesClient(credentials=creds)
        elif self.running_in_gcp:
            log.info("Using Compute Engine credentials")
            creds = compute_engine.Credentials()
            self.instances_client = compute_v1.InstancesClient(credentials=creds)
        else:
            log.info("No Service Account JSON provided; using Application Default Credentials")
            self.instances_client = compute_v1.InstancesClient()

        super()._initialize_check()

    def _list(self) -> List[str]:
        """Lists virtual machines configured.
        """
        try:
            request = compute_v1.ListInstancesRequest(
                    project=self.project,
                    zone=self.zone,
                    )
            instances = self.instances_client.list(request=request)
            return [instance.name for instance in instances]
        except Exception as e:
            raise CuckooMachineError(f"Failed to list instances in project '{self.project}' and zone '{self.zone}': {e}") from e

    def _status(self, label) -> str:
        """
        Get current status of a VM
        @param label: virtual machine label
        @return: status string
        """
        try:
            request = compute_v1.GetInstanceRequest(
                    project=self.project,
                    zone=self.zone,
                    instance=label
            )
            instance = self.instances_client.get(request=request)
        except Exception as e:
            raise CuckooMachineError(f"Error getting status for machine '{label}': {e}") from e

        # Reference: https://docs.cloud.google.com/compute/docs/instances/instance-lifecycle
        if instance.status in {"PENDING", "PROVISIONING", "STAGING", "REPAIRING"}:
            return self.PENDING
        elif instance.status == "RUNNING":
            return self.RUNNING
        elif instance.status in {"SUSPENDED", "SUSPENDING"}:
            return self.PAUSED
        elif instance.status == "TERMINATED":
            return self.POWEROFF
        elif instance.status in {"STOPPING", "PENDING_STOP"}:
            return self.ABORTED
        else:
            return self.ERROR

    def start(self, label):
        """
        Start a virtual machine.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting VM %s", label)
        try:
            if self._status(label) in (self.RUNNING, self.PENDING):
                log.warning("Trying to start a machine that is already running or pending: %s", label)
                return

            request = compute_v1.StartInstanceRequest(
                    project=self.project,
                    zone=self.zone,
                    instance=label
            )
            self.instances_client.start(request=request)
        except Exception as e:
            raise CuckooMachineError(f"Unable to start machine '{label}': {e}") from e

    def stop(self, label):
        """
        Stop a virtual machine.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping VM %s", label)
        try:
            if self._status(label) == self.POWEROFF:
                log.warning("Trying to stop a machine that is already stopped: %s", label)
                return

            request = compute_v1.StopInstanceRequest(
                    project=self.project,
                    zone=self.zone,
                    instance=label
            )
            self.instances_client.stop(request=request)
        except Exception as e:
            raise CuckooMachineError(f"Unable to stop machine '{label}': {e}") from e
