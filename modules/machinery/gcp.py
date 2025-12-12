import logging
import random
import string

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

    OPERATION_TIMEOUT = 120 # 2 minutes

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
        creds = None
        if self.json_key_path:
            creds = service_account.Credentials.from_service_account_file(self.json_key_path)
        elif self.running_in_gcp:
            log.info("Using Compute Engine credentials")
            creds = compute_engine.Credentials()
        else:
            log.info("No Service Account JSON provided; using Application Default Credentials")

        self.instances_client = compute_v1.InstancesClient(credentials=creds)
        self.disks_client = compute_v1.DisksClient(credentials=creds)

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
            snapshot = self.db.view_machine_by_label(label).snapshot
            if snapshot is not None:
                self._wait_status(label, self.POWEROFF)
                self._restore(label, snapshot)
        except Exception as e:
            raise CuckooMachineError(f"Unable to stop machine '{label}': {e}") from e

    def _restore(self, label, snapshot):
        """
        Restore a virtual machine according to the configured snapshot.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to restore.
        """
        log.debug("Restoring VM %s", label)
        try:
            request = compute_v1.GetInstanceRequest(
                    project=self.project,
                    zone=self.zone,
                    instance=label
            )
            instance = self.instances_client.get(request=request)
            if len(instance.disks) > 1:
                log.error("Unable to restore machine '%s': wrong number of disks", label)
                raise CuckooMachineError(f"Unable to restore machine '{label}': wrong number of disks")
            elif len(instance.disks) == 1:
                # Detach old disk
                old_disk = instance.disks[0]
                log.debug("Detaching disk %s", old_disk.device_name)
                request = compute_v1.DetachDiskInstanceRequest(
                        project=self.project,
                        zone=self.zone,
                        instance=label,
                        device_name=old_disk.device_name
                )
                operation = self.instances_client.detach_disk(request=request)
                operation.result(timeout=self.OPERATION_TIMEOUT)
                self._wait_and_check_operation(operation, label, "unable to detach disk")

                # Delete old disk
                log.debug("Deleting disk %s", old_disk.device_name)
                request = compute_v1.DeleteDiskRequest(
                        project=self.project,
                        zone=self.zone,
                        disk=old_disk.device_name
                )
                operation = self.disks_client.delete(request=request)
                self._wait_and_check_operation(operation, label, "unable to delete disk")

            # Create disk from snapshot
            new_disk_name = instance.name + ''.join(random.choices(string.ascii_lowercase, k=5))
            log.debug("Creating disk %s from snapshot %s", new_disk_name, snapshot)
            new_disk = compute_v1.Disk(
                    name=new_disk_name,
                    source_snapshot=f"projects/{self.project}/global/snapshots/{snapshot}",
                    zone=instance.zone
            )
            operation = self.disks_client.insert(
                    project=self.project,
                    zone=self.zone,
                    disk_resource=new_disk
            )
            operation.result(timeout=self.OPERATION_TIMEOUT)
            self._wait_and_check_operation(operation, label, "unable to create disk")

            # Attach new disk
            log.debug("Attaching disk %s", new_disk.name)
            request = compute_v1.AttachDiskInstanceRequest(
                    project=self.project,
                    zone=self.zone,
                    instance=label,
                    attached_disk_resource=compute_v1.AttachedDisk(
                            source=f"/projects/{self.project}/zones/{self.zone}/disks/{new_disk.name}",
                            mode="READ_WRITE",
                            auto_delete=True,
                            boot=True
                    )
            )
            operation = self.instances_client.attach_disk(request=request)
            self._wait_and_check_operation(operation, label, "unable to attach disk")
        except Exception as e:
            raise CuckooMachineError(f"Unable to restore machine '{label}': {e}") from e

    def _wait_and_check_operation(self, operation, label: str, error_message: str):
        """Waits for a GCP operation to complete and raises an error if it fails."""
        operation.result(timeout=self.OPERATION_TIMEOUT)
        if operation.error_code:
            log.error("Unable to restore machine '%s': %s. Error: %s", label, error_message, operation.error_message)
            raise CuckooMachineError(f"Unable to restore machine '{label}': {error_message}")
