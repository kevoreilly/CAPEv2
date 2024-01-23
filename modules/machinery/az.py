# Originally contributed by Check Point Software Technologies, Ltd.
# in https://github.com/CheckPointSW/Cuckoo-AWS.
# Modified by the Canadian Centre for Cyber Security to support Azure.

import logging
import socket
import threading
import time
import timeit

try:
    # Azure-specific imports
    # pip install azure-identity msrest msrestazure azure-mgmt-compute azure-mgmt-network
    from azure.identity import CertificateCredential, ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient, models
    from azure.mgmt.network import NetworkManagementClient
    from msrest.polling import LROPoller

    HAVE_AZURE = True
except ImportError:
    HAVE_AZURE = False
    print("Missing machinery-required libraries.")
    print("poetry run python -m pip install azure-identity msrest msrestazure azure-mgmt-compute azure-mgmt-network")

# Cuckoo-specific imports
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT
from lib.cuckoo.common.exceptions import (
    CuckooCriticalError,
    CuckooDependencyError,
    CuckooGuestCriticalTimeout,
    CuckooMachineError,
    CuckooOperationalError,
)
from lib.cuckoo.core.database import TASK_PENDING

# Only log INFO or higher from imported python packages
logging.getLogger("adal-python").setLevel(logging.INFO)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
logging.getLogger("azure.identity._internal.get_token_mixin").setLevel(logging.WARNING)
logging.getLogger("msal.authority").setLevel(logging.INFO)
logging.getLogger("msal.application").setLevel(logging.INFO)
logging.getLogger("msal.telemetry").setLevel(logging.INFO)
logging.getLogger("msal.token_cache").setLevel(logging.INFO)
logging.getLogger("msrest.universal_http").setLevel(logging.INFO)
logging.getLogger("msrest.service_client").setLevel(logging.INFO)
logging.getLogger("msrest.async_paging").setLevel(logging.INFO)
log = logging.getLogger(__name__)

# Timeout used for calls that shouldn't take longer than 5 minutes but somehow do
AZURE_TIMEOUT = 120

# Global variable which will maintain details about each machine pool
machine_pools = {}

# Global variable which will maintain state for platform scaling
is_platform_scaling = {}

# Explainer of how Azure VMSSs handle multiple requests such VM reimage, VM deletes or VMSS updates.
# If multiple operations are triggered one after another in a short duration on VMSSs in a resource group, they end up
# being overlapping operations. With overlapping operations, the latest operation comes in before the first one
# completes. This results in the latest operation preempting the previous operation and taking over its job. The
# preemption chain continues till 3 levels. After third preemption, VMSS stops further preemption, which means
# any further overlapping operation now has to wait for the previous one to complete.
# With this ^ in mind, we are only going to be running at most FOUR operations on any VMSS in a resource group at once,
# and since this is a restriction that we must live with, we will be using batch reimaging/deleting as well as many
# threadsafe operations.

# This is hard cap of 4 given the maximum preemption chain length of 4
MAX_CONCURRENT_VMSS_OPERATIONS = 4

# These global lists will be used for maintaining lists of ongoing operations on specific machines
vms_currently_being_reimaged = []
vms_currently_being_deleted = []

# These global lists will be used as a FIFO queue of sorts, except when used as a list
reimage_vm_list = []
delete_vm_list = []

# These are locks to provide for thread-safe operations
reimage_lock = threading.Lock()
delete_lock = threading.Lock()
vms_currently_being_deleted_lock = threading.Lock()

# This is the number of operations that are taking place at the same time
current_vmss_operations = 0


class Azure(Machinery):

    # Resource tag that indicates auto-scaling.
    AUTO_SCALE_CAPE_KEY = "AUTO_SCALE_CAPE"
    AUTO_SCALE_CAPE_VALUE = "True"
    AUTO_SCALE_CAPE_TAG = {AUTO_SCALE_CAPE_KEY: AUTO_SCALE_CAPE_VALUE}

    # Operating System Tag Prefixes
    WINDOWS_TAG_PREFIX = "win"
    LINUX_TAG_PREFIX = "ub"
    VALID_TAG_PREFIXES = [WINDOWS_TAG_PREFIX, LINUX_TAG_PREFIX]

    # Platform names
    WINDOWS_PLATFORM = "windows"
    LINUX_PLATFORM = "linux"

    def _initialize(self, module_name):
        """
        Overloading abstracts.py:_initialize()
        Read configuration.
        @param module_name: module name
        @raise CuckooDependencyError: if there is a problem with the dependencies call
        """
        self.module_name = module_name
        mmanager_opts = self.options.get(module_name)
        if not isinstance(mmanager_opts["scale_sets"], list):
            mmanager_opts["scale_sets"] = mmanager_opts["scale_sets"].strip().split(",")

        # Replace a list of IDs with dictionary representations
        scale_sets = mmanager_opts.pop("scale_sets")
        mmanager_opts["scale_sets"] = {}

        for scale_set_id in scale_sets:
            try:
                scale_set_opts = self.options.get(scale_set_id.strip())
                scale_set_opts["id"] = scale_set_id.strip()

                # Strip parameters.
                for key, value in scale_set_opts.items():
                    if value and isinstance(value, str):
                        scale_set_opts[key] = value.strip()

                if "initial_pool_size" not in scale_set_opts:
                    raise AttributeError("'initial_pool_size' not present in scale set configuration")

                # If the initial pool size is 0, then post-initialization we will have 0 machines available for a
                # scale set, which is bad for Cuckoo logic
                if scale_set_opts["initial_pool_size"] <= 0:
                    raise CuckooCriticalError(
                        f"The initial pool size for VMSS '{scale_set_id}'  is 0. Please set it to a positive integer."
                    )

                # Insert the scale_set_opts into the module.scale_sets attribute
                mmanager_opts["scale_sets"][scale_set_id] = scale_set_opts

            except (AttributeError, CuckooOperationalError) as e:
                log.warning(f"Configuration details about scale set {scale_set_id.strip()} are missing: {e}")
                continue

    def _initialize_check(self):
        """
        Overloading abstracts.py:_initialize_check()
        Running checks against Azure that the configuration is correct.
        @param module_name: module name, currently not used be required
        @raise CuckooDependencyError: if there is a problem with the dependencies call
        """
        if not HAVE_AZURE:
            raise CuckooDependencyError("Unable to import Azure packages")

        # Set the flag that indicates that the system is initializing
        self.initializing = True

        # We will be using this as a source of truth for the VMSS configs
        self.required_vmsss = {
            vmss_name: {"exists": False, "image": None, "platform": None, "tag": None, "initial_pool_size": None}
            for vmss_name in self.options.az.scale_sets
        }

        # Starting the thread that sets API clients periodically
        self._thr_refresh_clients()

        # Starting the thread that scales the machine pools periodically
        self._thr_machine_pool_monitor()

        # Initialize the VMSSs that we will be using and not using
        self._set_vmss_stage()

        # Set the flag that indicates that the system is not initializing
        self.initializing = False

    def _get_credentials(self):
        """
        Used to instantiate the Azure ClientSecretCredential object.
        @return: an Azure ClientSecretCredential object
        """

        credentials = None
        if self.options.az.secret and self.options.az.secret != "<secret>":
            # Instantiates the ClientSecretCredential object using
            # Azure client ID, secret and Azure tenant ID
            credentials = ClientSecretCredential(
                client_id=self.options.az.client_id,
                client_secret=self.options.az.secret,
                tenant_id=self.options.az.tenant,
            )
        else:
            # Instantiates the CertificateCredential object using
            # Azure client ID, secret and Azure tenant ID
            credentials = CertificateCredential(
                client_id=self.options.az.client_id,
                tenant_id=self.options.az.tenant,
                certificate_path=self.options.az.certificate_path,
                password=self.options.az.certificate_password,
            )
        return credentials

    def _thr_refresh_clients(self):
        """
        A thread on a 30 minute timer that refreshes the network
        and compute clients using an updated ClientSecretCredential
        object.
        """
        log.debug(f"Connecting to Azure for the region '{self.options.az.region_name}'.")

        # Getting an updated ClientSecretCredential
        credentials = self._get_credentials()

        # Instantiates an Azure NetworkManagementClient using
        # ClientSecretCredential and subscription ID
        self.network_client = NetworkManagementClient(credential=credentials, subscription_id=self.options.az.subscription_id)

        # Instantiates an Azure ComputeManagementClient using
        # ClientSecretCredential and subscription ID
        self.compute_client = ComputeManagementClient(credential=credentials, subscription_id=self.options.az.subscription_id)

        # Refresh clients every half hour
        threading.Timer(1800, self._thr_refresh_clients).start()

    def _thr_machine_pool_monitor(self):
        """
        A thread on a 5 minute timer that scales the machine pools to
        appropriate levels.
        """
        # Only do it post-initialization
        if self.initializing:
            pass
        else:
            log.debug("Monitoring the machine pools...")
            for _, vals in self.required_vmsss.items():
                threading.Thread(target=self._thr_scale_machine_pool, args=(vals["tag"],)).start()

        # Check the machine pools every 5 minutes
        threading.Timer(300, self._thr_machine_pool_monitor).start()

    def _set_vmss_stage(self):
        """
        Ready. Set. Action! Set the stage for the VMSSs
        """
        global machine_pools, is_platform_scaling, current_vmss_operations, reimage_vm_list, delete_vm_list

        # Now assign the gallery image to the VMSS
        for scale_set_id, scale_set_values in self.options.az.scale_sets.items():
            try:
                gallery_image = Azure._azure_api_call(
                    self.options.az.sandbox_resource_group,
                    self.options.az.gallery_name,
                    scale_set_values.gallery_image_name,
                    operation=self.compute_client.gallery_images.get,
                )
            except CuckooMachineError:
                raise CuckooCriticalError(f"Gallery image '{scale_set_values.gallery_image_name}' does not exist")

            # Map the Image Reference to the VMSS
            self.required_vmsss[scale_set_id]["platform"] = scale_set_values.platform.capitalize()
            self.required_vmsss[scale_set_id]["tag"] = scale_set_values.pool_tag
            self.required_vmsss[scale_set_id]["image"] = models.ImageReference(id=gallery_image.id)
            self.required_vmsss[scale_set_id]["initial_pool_size"] = int(scale_set_values.initial_pool_size)

        # All required VMSSs must have an image reference, tag and os
        for required_vmss_name, required_vmss_values in self.required_vmsss.items():
            if required_vmss_values["image"] is None:
                raise CuckooCriticalError(f"The VMSS '{required_vmss_name}' does not have an image reference.")
            elif required_vmss_values["tag"] is None:
                raise CuckooCriticalError(f"The VMSS '{required_vmss_name}' does not have an tag.")
            elif required_vmss_values["platform"] is None:
                raise CuckooCriticalError(f"The VMSS '{required_vmss_name}' does not have an OS value.")
            elif required_vmss_values["initial_pool_size"] is None:
                raise CuckooCriticalError(f"The VMSS '{required_vmss_name}' does not have an initial pool size.")

        # Get all VMSSs in Resource Group
        existing_vmsss = Azure._azure_api_call(
            self.options.az.sandbox_resource_group,
            operation=self.compute_client.virtual_machine_scale_sets.list,
        )

        # Delete incorrectly named VMSSs or mark them as existing
        for vmss in existing_vmsss:

            # If a VMSS does not have any tags or does not have the tag that we use to indicate that it is used for
            # Cuckoo (AUTO_SCALE_CAPE key-value pair), ignore
            if not vmss.tags or not vmss.tags.get(Azure.AUTO_SCALE_CAPE_KEY) == Azure.AUTO_SCALE_CAPE_VALUE:

                # Unless! They have one of the required names of the VMSSs that we are going to create
                if vmss.name in self.required_vmsss.keys():
                    async_delete_vmss = Azure._azure_api_call(
                        self.options.az.sandbox_resource_group,
                        vmss.name,
                        polling_interval=1,
                        operation=self.compute_client.virtual_machine_scale_sets.begin_delete,
                    )
                    _ = self._handle_poller_result(async_delete_vmss)
                # NEXT
                continue

            # The VMSS has tags and the tags include the AUTO_SCALE_CAPE key-value pair
            if vmss.name in self.required_vmsss.keys():
                required_vmss = self.required_vmsss[vmss.name]

                # Note that the VMSS exists and that we do not need to create another one
                required_vmss["exists"] = True

                # This flag is used to determine if we have to update the VMSS
                update_vmss = False

                # Check if image reference is out-of-date with the one in the configuration
                if required_vmss["image"].id != vmss.virtual_machine_profile.storage_profile.image_reference.id:
                    # If so, update it
                    update_vmss = True
                    vmss.virtual_machine_profile.storage_profile.image_reference.id = required_vmss["image"].id

                # Check if the capacity of VMSS matches the initial pool size from the configuration
                if self.options.az.reset_pool_size and vmss.sku.capacity != required_vmss["initial_pool_size"]:
                    # If no, update it
                    update_vmss = True
                    vmss.sku.capacity = required_vmss["initial_pool_size"]

                # Initialize key-value pair for VMSS with specific details
                machine_pools[vmss.name] = {
                    "size": int(vmss.sku.capacity),
                    "is_scaling": False,
                    "is_scaling_down": False,
                    "wait": False,
                }

                if update_vmss:
                    update_vmss_image = Azure._azure_api_call(
                        self.options.az.sandbox_resource_group,
                        vmss.name,
                        vmss,
                        polling_interval=1,
                        operation=self.compute_client.virtual_machine_scale_sets.begin_update,
                    )
                    _ = self._handle_poller_result(update_vmss_image)
            elif not self.options.az.multiple_capes_in_sandbox_rg:
                # VMSS does not have the required name but has the tag that we associate with being a
                # correct VMSS
                Azure._azure_api_call(
                    self.options.az.sandbox_resource_group,
                    vmss.name,
                    operation=self.compute_client.virtual_machine_scale_sets.begin_delete,
                )

        try:
            self.subnet_id = Azure._azure_api_call(
                self.options.az.vnet_resource_group,
                self.options.az.vnet,
                self.options.az.subnet,
                operation=self.network_client.subnets.get,
            ).id  # note the id attribute here
        except CuckooMachineError:
            raise CuckooCriticalError(
                f"Subnet '{self.options.az.subnet}' does not exist in Virtual Network '{self.options.az.vnet}'"
            )

        # Initialize the platform scaling state monitor
        is_platform_scaling = {Azure.WINDOWS_PLATFORM: False, Azure.LINUX_PLATFORM: False}

        # Let's get the number of CPUs associated with the SKU (instance_type)
        # If we want to programmatically determine the number of cores for the sku
        if self.options.az.find_number_of_cores_for_sku or self.options.az.instance_type_cores == 0:
            resource_skus = Azure._azure_api_call(
                filter=f"location={self.options.az.region_name}",
                operation=self.compute_client.resource_skus.list,
            )
            resource_details = None
            for item in resource_skus:
                if self.options.az.region_name.lower() not in [location.lower() for location in item.locations]:
                    continue
                if item.name == self.options.az.instance_type:
                    resource_details = item
                    break

            if resource_details:
                for capability in resource_details.capabilities:
                    if capability.name == "vCPUs":
                        self.instance_type_cpus = int(capability.value)
                        break
            else:
                # TODO: Justify why 4 is a good default value
                self.instance_type_cpus = 4
        # Do not programmatically determine the number of cores for the sku
        else:
            self.instance_type_cpus = self.options.az.instance_type_cores

        # Create required VMSSs that don't exist yet
        vmss_creation_threads = []
        vmss_reimage_threads = []
        for vmss, vals in self.required_vmsss.items():
            if vals["exists"] and not self.options.az.just_start:
                if machine_pools[vmss]["size"] == 0:
                    self._thr_scale_machine_pool(self.options.az.scale_sets[vmss].pool_tag, True if vals["platform"] else False),
                else:
                    # Reimage VMSS!
                    thr = threading.Thread(
                        target=self._thr_reimage_vmss,
                        args=(vmss,),
                    )
                    vmss_reimage_threads.append(thr)
                    thr.start()
            else:
                # Create VMSS!
                thr = threading.Thread(target=self._thr_create_vmss, args=(vmss, vals["image"], vals["platform"]))
                vmss_creation_threads.append(thr)
                thr.start()

        # Wait for everything to complete!
        for thr in vmss_reimage_threads + vmss_creation_threads:
            thr.join()

        # Initialize the batch reimage threads. We want at most 4 batch reimaging threads
        # so that if no VMSS scaling or batch deleting is taking place (aka we are receiving constant throughput of
        # tasks and have the appropriate number of VMs created) then we'll perform batch reimaging at an optimal rate.
        workers = []
        for _ in range(MAX_CONCURRENT_VMSS_OPERATIONS):
            reimage_worker = threading.Thread(target=self._thr_reimage_list_reader)
            reimage_worker.daemon = True
            workers.append(reimage_worker)

        # Initialize a single batch delete thread because we don't care when these operations finish
        delete_worker = threading.Thread(target=self._thr_delete_list_reader)
        delete_worker.daemon = True
        workers.append(delete_worker)

        # Start em up!
        for worker in workers:
            worker.start()

    def start(self, _):
        # NOTE: Machines are always started. ALWAYS
        pass

    def stop(self, label):
        """
        If the VMSS is in the "scaling-down" state, delete machine,
        otherwise reimage it.
        @param label: virtual machine label
        @return: End method call
        """
        global reimage_vm_list, delete_vm_list, vms_currently_being_deleted
        log.debug(f"Stopping machine '{label}'")
        # Parse the tag and instance id out to confirm which VMSS to modify
        vmss_name, instance_id = label.split("_")
        # If we aren't scaling down, then reimage
        if not machine_pools[vmss_name]["is_scaling_down"]:
            with reimage_lock:
                reimage_vm_list.append({"vmss": vmss_name, "id": instance_id, "time_added": time.time()})
            # Two stages until the VM can be consider reimaged
            # Stage 1: Label is not in queue-list
            # Stage 2: Label is not in vms_currently_being_reimaged
            # It can be assumed that at this point in time that the label is in the reimage_vm_list
            label_in_reimage_vm_list = True
            while label_in_reimage_vm_list or label in vms_currently_being_reimaged:
                time.sleep(5)
                with reimage_lock:
                    label_in_reimage_vm_list = label in [f"{vm['vmss']}_{vm['id']}" for vm in reimage_vm_list]
        else:
            self.delete_machine(label)

    def availables(self, label=None, platform=None, tags=None, arch=None, include_reserved=False, os_version=[]):
        """
        Overloading abstracts.py:availables() to utilize the auto-scale option.
        """
        if tags:
            for tag in tags:
                # If VMSS is in the "wait" state, then WAIT
                vmss_name = next((name for name, vals in self.required_vmsss.items() if vals["tag"] == tag), None)
                if vmss_name is None:
                    return 0
                if machine_pools[vmss_name]["wait"]:
                    log.debug("Machinery is not ready yet...")
                    return 0

        return super(Azure, self).availables(
            label=label, platform=platform, tags=tags, arch=arch, include_reserved=include_reserved, os_version=os_version
        )

    def acquire(self, machine_id=None, platform=None, tags=None, arch=None, os_version=[], need_scheduled=False):
        """
        Overloading abstracts.py:acquire() to utilize the auto-scale option.
        @param machine_id: the name of the machine to be acquired
        @param platform: the platform of the machine's operating system to be acquired
        @param tags: any tags that are associated with the machine to be acquired
        @param arch: the architecture of the operating system
        @return: dict representing machine object from DB
        """
        base_class_return_value = super(Azure, self).acquire(
            machine_id=machine_id, platform=platform, tags=tags, arch=arch, os_version=os_version, need_scheduled=need_scheduled
        )
        if base_class_return_value and base_class_return_value.name:
            vmss_name, _ = base_class_return_value.name.split("_")

            # Get the VMSS name by the tag
            if not machine_pools[vmss_name]["is_scaling"]:
                # Start it and forget about it
                threading.Thread(
                    target=self._thr_scale_machine_pool,
                    args=(self.options.az.scale_sets[vmss_name].pool_tag, True if platform else False),
                ).start()

        return base_class_return_value

    def _add_machines_to_db(self, vmss_name):
        """
        Adding machines to database that did not exist there before.
        @param vmss_name: the name of the VMSS to be queried
        """
        try:
            log.debug(f"Adding machines to database for {vmss_name}.")
            # We don't want to re-add machines! Therefore, let's see what we're working with
            machines_in_db = self.db.list_machines()
            db_machine_labels = [machine.label for machine in machines_in_db]
            # We want to avoid collisions where the IP is already associated with a machine
            db_machine_ips = [machine.ip for machine in machines_in_db]

            # Get all VMs in the VMSS
            paged_vmss_vms = Azure._azure_api_call(
                self.options.az.sandbox_resource_group,
                vmss_name,
                operation=self.compute_client.virtual_machine_scale_set_vms.list,
            )

            # Get all network interface cards for the machines in the VMSS
            paged_vmss_vm_nics = Azure._azure_api_call(
                self.options.az.sandbox_resource_group,
                vmss_name,
                operation=self.network_client.network_interfaces.list_virtual_machine_scale_set_network_interfaces,
            )

            # Turn the Paged result into a list
            vmss_vm_nics = [vmss_vm_nic for vmss_vm_nic in paged_vmss_vm_nics]

            # This will be used if we are in the initializing phase of the system
            ready_vmss_vm_threads = {}
            with vms_currently_being_deleted_lock:
                vms_to_avoid_adding = vms_currently_being_deleted
            for vmss_vm in paged_vmss_vms:
                if vmss_vm.name in db_machine_labels:
                    # Don't add it if it already exists!
                    continue
                if vmss_vm.name in vms_to_avoid_adding:
                    # Don't add it if it is currently being deleted!
                    log.debug(f"{vmss_vm.name} is currently being deleted!")
                    continue
                # According to Microsoft, the OS type is...
                platform = vmss_vm.storage_profile.os_disk.os_type.lower()

                if not vmss_vm.network_profile:
                    log.error(f"{vmss_vm.name} does not have a network profile")
                    continue

                vmss_vm_nic = next(
                    (
                        vmss_vm_nic
                        for vmss_vm_nic in vmss_vm_nics
                        if vmss_vm.network_profile.network_interfaces[0].id.lower() == vmss_vm_nic.id.lower()
                    ),
                    None,
                )
                if not vmss_vm_nic:
                    log.error(
                        f"{vmss_vm.network_profile.network_interfaces[0].id.lower()} does not match any NICs in {[vmss_vm_nic.id.lower() for vmss_vm_nic in vmss_vm_nics]}"
                    )
                    continue
                # Sets "new_machine" object in configuration object to
                # avoid raising an exception.
                setattr(self.options, vmss_vm.name, {})

                private_ip = vmss_vm_nic.ip_configurations[0].private_ip_address
                if private_ip in db_machine_ips:
                    log.error(f"The IP '{private_ip}' is already associated with a machine in the DB. Moving on...")
                    continue

                # Add machine to DB.
                # TODO: What is the point of name vs label?
                self.db.add_machine(
                    name=vmss_vm.name,
                    label=vmss_vm.name,
                    ip=private_ip,
                    platform=platform,
                    tags=self.options.az.scale_sets[vmss_name].pool_tag,
                    arch=self.options.az.scale_sets[vmss_name].arch,
                    interface=self.options.az.interface,
                    snapshot=vmss_vm.storage_profile.image_reference.id,
                    resultserver_ip=self.options.az.resultserver_ip,
                    resultserver_port=self.options.az.resultserver_port,
                    reserved=False,
                )
                # When we aren't initializing the system, the machine will immediately become available in DB
                # When we are initializing, we're going to wait for the machine to be have the Cuckoo agent all set up
                if self.initializing and self.options.az.wait_for_agent_before_starting:
                    thr = threading.Thread(
                        target=Azure._thr_wait_for_ready_machine,
                        args=(
                            vmss_vm.name,
                            private_ip,
                        ),
                    )
                    ready_vmss_vm_threads[vmss_vm.name] = thr
                    thr.start()

            if self.initializing:
                for vm, thr in ready_vmss_vm_threads.items():
                    try:
                        thr.join()
                    except CuckooGuestCriticalTimeout:
                        log.debug(f"Rough start for {vm}, deleting.")
                        self.delete_machine(vm)
                        raise
        except Exception as e:
            log.error(repr(e), exc_info=True)

    def _delete_machines_from_db_if_missing(self, vmss_name):
        """
        Delete machine from database if it does not exist in the VMSS.
        @param vmss_name: the name of the VMSS to be queried
        """
        log.debug(f"Deleting machines from database if they do not exist in the VMSS {vmss_name}.")
        # Get all VMs in the VMSS
        paged_vmss_vms = Azure._azure_api_call(
            self.options.az.sandbox_resource_group,
            vmss_name,
            operation=self.compute_client.virtual_machine_scale_set_vms.list,
        )

        # Turn the Paged result into a list
        vmss_vm_names = [vmss_vm.name for vmss_vm in paged_vmss_vms]

        for machine in self.db.list_machines():
            # If machine entry in database is part of VMSS but machine in VMSS does not exist, delete
            if vmss_name in machine.label and machine.label not in vmss_vm_names:
                self.delete_machine(machine.label, delete_from_vmss=False)

    def delete_machine(self, label, delete_from_vmss=True):
        """
        Overloading abstracts.py:delete_machine()
        """
        global vms_currently_being_deleted

        _ = super(Azure, self).delete_machine(label)

        if delete_from_vmss:
            vmss_name, instance_id = label.split("_")
            with vms_currently_being_deleted_lock:
                vms_currently_being_deleted.append(label)
            with delete_lock:
                delete_vm_list.append({"vmss": vmss_name, "id": instance_id, "time_added": time.time()})

    @staticmethod
    def _thr_wait_for_ready_machine(machine_name, machine_ip):
        """
        Static method that is used to determine if the agent is running on a machine yet.
        @param machine_name: the name of the machine waited for. NOTE param is only used for logging.
        @param machine_ip: the IP of the machine we are waiting for.
        @return: End method call
        """
        # Majority of this code is copied from cuckoo/core/guest.py:GuestManager.wait_available()
        timeout = Config("cuckoo").timeouts.vm_state
        start = timeit.default_timer()
        while True:
            try:
                socket.create_connection((machine_ip, CUCKOO_GUEST_PORT), 1).close()
                # We did it!
                break
            except socket.timeout:
                log.debug(f"{machine_name}: Initializing...")
            except socket.error:
                log.debug(f"{machine_name}: Initializing...")
            time.sleep(10)

            if timeit.default_timer() - start >= timeout:
                # We didn't do it :(
                raise CuckooGuestCriticalTimeout(
                    f"Machine {machine_name}: the guest initialization hit the critical " "timeout, analysis aborted."
                )
        log.debug(f"Machine {machine_name} was created and available in {round(timeit.default_timer() - start)}s")

    @staticmethod
    def _azure_api_call(*args, **kwargs):
        """
        This method is used as a common place for all Azure API calls
        @param args: any argument that an Azure API call takes
        @param kwargs: the API call operation, and sometimes tags
        @raise CuckooMachineError: if there is a problem with the Azure call
        @return: dict containing results of API call
        """
        # I figured this was the most concrete way to guarantee that an API method was being passed
        if not kwargs["operation"]:
            raise Exception("kwargs in _azure_api_call requires 'operation' parameter.")
        operation = kwargs.pop("operation")

        # This is used for logging
        api_call = f"{operation}({args},{kwargs})"

        try:
            log.debug(f"Trying {api_call}")
            results = operation(*args, **kwargs)
        except Exception as exc:
            # For ClientRequestErrors, they do not have the attribute 'error'
            error = exc.error.error if getattr(exc, "error", False) else exc
            log.warning(
                f"Failed to {api_call} due to the Azure error '{error}': '{exc.message if hasattr(exc, 'message') else repr(exc)}'."
            )
            if "NotFound" in repr(exc) or (hasattr(exc, "status_code") and exc.status_code == 404):
                # Note that this exception is used to represent if an Azure resource
                # has not been found, not just machines
                raise CuckooMachineError(f"{error}:{exc.message if hasattr(exc, 'message') else repr(exc)}")
            else:
                raise CuckooMachineError(f"{error}:{exc.message if hasattr(exc, 'message') else repr(exc)}")
        if type(results) == LROPoller:
            # Log the subscription limits
            headers = results._response.headers
            log.debug(
                f"API Charge: {headers['x-ms-request-charge']}; Remaining Calls: {headers['x-ms-ratelimit-remaining-resource']}"
            )
        return results

    def _thr_create_vmss(self, vmss_name, vmss_image_ref, vmss_image_os):
        """
        Creates a Virtual Machine Scale Set
        @param vmss_name: The name of the VMSS to be created
        @param vmss_image_ref: The image reference to be used for the VMSS
        @param vmss_image_os: The platform of the image
        @param vmss_tag: the tag used that represents the OS image
        """
        global machine_pools, current_vmss_operations

        vmss_managed_disk = models.VirtualMachineScaleSetManagedDiskParameters(
            storage_account_type=self.options.az.storage_account_type
        )
        vmss_os_disk = models.VirtualMachineScaleSetOSDisk(
            create_option="FromImage",
            os_type=vmss_image_os,
            managed_disk=vmss_managed_disk,
            # Ephemeral disk time
            caching="ReadOnly",
            diff_disk_settings=models.DiffDiskSettings(option="Local"),
        )
        vmss_storage_profile = models.VirtualMachineScaleSetStorageProfile(
            image_reference=vmss_image_ref,
            os_disk=vmss_os_disk,
        )
        vmss_dns_settings = models.VirtualMachineScaleSetNetworkConfigurationDnsSettings(
            dns_servers=self.options.az.dns_server_ips.strip().split(",")
        )
        vmss_ip_config = models.VirtualMachineScaleSetIPConfiguration(
            name="vmss_ip_config",
            subnet=models.ApiEntityReference(id=self.subnet_id),
            private_ip_address_version="IPv4",
        )
        vmss_network_config = models.VirtualMachineScaleSetNetworkConfiguration(
            name="vmss_network_config",
            dns_settings=vmss_dns_settings,
            ip_configurations=[vmss_ip_config],
            primary=True,
        )
        vmss_network_profile = models.VirtualMachineScaleSetNetworkProfile(network_interface_configurations=[vmss_network_config])
        # If the user wants spot instances, then give them spot instances!
        if self.options.az.spot_instances:
            vmss_vm_profile = models.VirtualMachineScaleSetVMProfile(
                storage_profile=vmss_storage_profile,
                network_profile=vmss_network_profile,
                # Note: The following key value pairs are for Azure spot instances
                priority=models.VirtualMachinePriorityTypes.spot,
                eviction_policy=models.VirtualMachineEvictionPolicyTypes.delete,
                # Note: This value may change depending on your needs.
                billing_profile=models.BillingProfile(max_price=float(-1)),
            )
        else:
            vmss_vm_profile = models.VirtualMachineScaleSetVMProfile(
                storage_profile=vmss_storage_profile,
                network_profile=vmss_network_profile,
            )
        vmss = models.VirtualMachineScaleSet(
            location=self.options.az.region_name,
            tags=Azure.AUTO_SCALE_CAPE_TAG,
            sku=models.Sku(name=self.options.az.instance_type, capacity=self.required_vmsss[vmss_name]["initial_pool_size"]),
            upgrade_policy=models.UpgradePolicy(mode="Automatic"),
            virtual_machine_profile=vmss_vm_profile,
            overprovision=False,
            # When true this limits the scale set to a single placement group, of max size 100 virtual machines.
            single_placement_group=False,
            scale_in_policy=models.ScaleInPolicy(rules=[models.VirtualMachineScaleSetScaleInRules.newest_vm]),
            spot_restore_policy=(
                models.SpotRestorePolicy(enabled=True, restore_timeout="PT30M") if self.options.az.spot_instances else None
            ),
        )
        if not self.options.az.just_start:
            async_vmss_creation = Azure._azure_api_call(
                self.options.az.sandbox_resource_group,
                vmss_name,
                vmss,
                polling_interval=1,
                operation=self.compute_client.virtual_machine_scale_sets.begin_create_or_update,
            )
            _ = self._handle_poller_result(async_vmss_creation)

        # Initialize key-value pair for VMSS with specific details
        machine_pools[vmss_name] = {
            "size": self.required_vmsss[vmss_name]["initial_pool_size"],
            "is_scaling": False,
            "is_scaling_down": False,
            "wait": False,
        }
        self._add_machines_to_db(vmss_name)

    def _thr_reimage_vmss(self, vmss_name):
        """
        Reimage the VMSS
        @param vmss_name: the name of the VMSS to be reimage
        """
        # Reset all machines via begin_reimage_all
        try:
            async_reimage_all = Azure._azure_api_call(
                self.options.az.sandbox_resource_group,
                vmss_name,
                polling_interval=1,
                operation=self.compute_client.virtual_machine_scale_sets.begin_reimage_all,
            )
            _ = self._handle_poller_result(async_reimage_all)
        except CuckooMachineError as e:
            # Possible error: 'BadRequest': 'The VM {id} creation in Virtual Machine Scale Set {vmss-name} with
            # ephemeral disk is not complete. Please trigger a restart if required.'
            if "BadRequest" in repr(e):
                async_restart_vmss = Azure._azure_api_call(
                    self.options.az.sandbox_resource_group,
                    vmss_name,
                    polling_interval=1,
                    operation=self.compute_client.virtual_machine_scale_sets.restart,
                )
                _ = self._handle_poller_result(async_restart_vmss)
            else:
                log.error(repr(e), exc_info=True)
                raise
        self._add_machines_to_db(vmss_name)

    def _thr_scale_machine_pool(self, tag, per_platform=False):
        """
        Expand/Reduce the machine pool based on the number of queued relevant tasks
        @param tag: the OS tag of the machine pool to be scaled
        @param per_platform: A boolean flag indicating that we should scale machine pools "per platform" vs. "per tag"
        @return: Ends method call
        """
        global machine_pools, is_platform_scaling, current_vmss_operations

        platform = None
        if per_platform and Azure.WINDOWS_TAG_PREFIX in tag:
            platform = Azure.WINDOWS_PLATFORM
        elif per_platform and Azure.LINUX_TAG_PREFIX in tag:
            platform = Azure.LINUX_PLATFORM

        # If the designated VMSS is already being scaled for the given platform, don't mess with it
        if platform and is_platform_scaling[platform]:
            return

        # Get the VMSS name by the tag
        vmss_name = next(name for name, vals in self.required_vmsss.items() if vals["tag"] == tag)

        # TODO: Remove large try-catch once all bugs have been caught
        # It has been observed that there are times when the is_scaling flag is not returned to False even though
        # scaling has completed. Therefore we need this try-catch to figure out why.
        try:
            # If this VMSS is already being scaled, don't mess with it
            if machine_pools[vmss_name]["is_scaling"]:
                return

            # This is the flag that is used to indicate if the VMSS is being scaled by a thread
            machine_pools[vmss_name]["is_scaling"] = True

            # This is the flag that is used to indicate if a designated VMSS has been selected for a platform and if
            # it is being scaled by a thread
            if platform:
                is_platform_scaling[platform] = True

            relevant_machines = self._get_relevant_machines(tag)
            number_of_relevant_machines = len(relevant_machines)
            machine_pools[vmss_name]["size"] = number_of_relevant_machines
            relevant_task_queue = self._get_number_of_relevant_tasks(tag, platform)

            # The scaling technique we will use is a tweaked version of the Leaky Bucket, where we
            # only scale down if the relevant task queue is empty.

            # If there are no relevant tasks in the queue, scale to the bare minimum pool size
            if relevant_task_queue == 0:
                number_of_relevant_machines_required = self.required_vmsss[vmss_name]["initial_pool_size"]
            else:
                number_of_relevant_machines_required = int(
                    round(relevant_task_queue * (1 + float(self.options.az.overprovision) / 100))
                )

            if number_of_relevant_machines_required < self.required_vmsss[vmss_name]["initial_pool_size"]:
                number_of_relevant_machines_required = self.required_vmsss[vmss_name]["initial_pool_size"]
            elif number_of_relevant_machines_required > self.options.az.scale_set_limit:
                number_of_relevant_machines_required = self.options.az.scale_set_limit

            number_of_machines = len(self.db.list_machines())
            projected_total_machines = number_of_machines - number_of_relevant_machines + number_of_relevant_machines_required

            if projected_total_machines > self.options.az.total_machines_limit:
                non_relevant_machines = number_of_machines - number_of_relevant_machines
                number_of_relevant_machines_required = self.options.az.total_machines_limit - non_relevant_machines
                if number_of_relevant_machines_required < 0:
                    number_of_relevant_machines_required = self.required_vmsss[vmss_name]["initial_pool_size"]

            # Let's confirm that this number is actually achievable
            usages = Azure._azure_api_call(self.options.az.region_name, operation=self.compute_client.usage.list)
            usage_to_look_for = None
            if self.options.az.spot_instances:
                usage_to_look_for = "lowPriorityCores"
            else:
                # TODO: If not using spot instances, somehow figure out the usages key to determine a scaling limit for
                pass

            if usage_to_look_for:
                usage = next((item for item in usages if item.name.value == usage_to_look_for), None)

                if usage:
                    number_of_new_cpus_required = self.instance_type_cpus * (
                        number_of_relevant_machines_required - number_of_machines
                    )
                    # Leaving at least five spaces in the usage quota for a spot VM, let's not push it!
                    number_of_new_cpus_available = int(usage.limit) - usage.current_value - int(self.instance_type_cpus * 5)
                    if number_of_new_cpus_available < 0:
                        number_of_relevant_machines_required = machine_pools[vmss_name]["size"]
                    elif number_of_new_cpus_required > number_of_new_cpus_available:
                        old_number_of_relevant_machines_required = number_of_relevant_machines_required
                        number_of_relevant_machines_required = (
                            number_of_relevant_machines + number_of_new_cpus_available / self.instance_type_cpus
                        )
                        log.debug(
                            f"Quota could be exceeded with projected number of machines ({old_number_of_relevant_machines_required}). Setting new limit to {number_of_relevant_machines_required}"
                        )

            if machine_pools[vmss_name]["size"] == number_of_relevant_machines_required:
                # Check that VMs in DB actually exist in the VMSS. There is a possibility that
                # Azure will delete a machine in a VMSS that has not been used in a while. So the machine_pools value
                # will not be up-to-date
                self._delete_machines_from_db_if_missing(vmss_name)
                # Update the VMSS size accordingly
                machine_pools[vmss_name]["size"] = len(self._get_relevant_machines(tag))
                log.debug(f"The size of the machine pool {vmss_name} is already the size that we want")
                machine_pools[vmss_name]["is_scaling"] = False
                if platform:
                    is_platform_scaling[platform] = False
                return

            # This value will be used for adding or deleting machines from the database
            # NOTE: If you set the VMSS capacity to 4, then delete a VM, the capacity is set to 3 for some reason.
            # Therefore we want to grab the initial capacity from the global variable before machines are deleted,
            # since the vmss.sku.capacity variable is unreliable.
            initial_capacity = machine_pools[vmss_name]["size"]

            # Time to scale down!
            if number_of_relevant_machines_required < initial_capacity:
                # Creating these variables to be used to assist with the scaling down process
                initial_number_of_locked_relevant_machines = len([machine for machine in relevant_machines if machine.locked])
                initial_number_of_unlocked_relevant_machines = (
                    number_of_relevant_machines - initial_number_of_locked_relevant_machines
                )

                # The system is at rest when no relevant tasks are in the queue and no relevant machines are locked
                if relevant_task_queue == initial_number_of_locked_relevant_machines == 0:
                    # The VMSS will scale in via the ScaleInPolicy.
                    machine_pools[vmss_name]["wait"] = True
                    log.debug(f"System is at rest, scale down {vmss_name} capacity and delete machines.")
                # System is not at rest, but task queue is 0, therefore set machines in use to delete
                elif relevant_task_queue == 0:
                    machine_pools[vmss_name]["is_scaling_down"] = True
                    start_time = timeit.default_timer()
                    # Wait until currently locked machines are deleted to the number that we require
                    while number_of_relevant_machines > number_of_relevant_machines_required:
                        # Since we're sleeping 1 second between iterations of this while loop, if there are available
                        # machines waiting to be assigned tasks and a new task comes down the pipe then there will be
                        # no queue and instead the # of locked relevant machines will increase (or unlocked relevant
                        # machines will decrease). Either one indicates that a new task has been submitted and therefore
                        # the "scaling down" process should exit. This is to prevent scaling down and up so often.
                        updated_number_of_locked_relevant_machines = len(
                            [machine for machine in relevant_machines if machine.locked]
                        )
                        updated_number_of_unlocked_relevant_machines = (
                            number_of_relevant_machines - updated_number_of_locked_relevant_machines
                        )

                        # We don't want to be stuck in this for longer than the timeout specified
                        if timeit.default_timer() - start_time > AZURE_TIMEOUT:
                            log.debug(f"Breaking out of the while loop within the scale down section for {vmss_name}.")
                            break
                        # Get the updated number of relevant machines required
                        relevant_task_queue = self._get_number_of_relevant_tasks(tag)
                        # As soon as a task is in the queue or has been assigned to a machine, we do not want to scale down any more.
                        # Deleting an instance affects the capacity of the VMSS, so we do not need to update it.
                        if (
                            relevant_task_queue
                            or updated_number_of_locked_relevant_machines > initial_number_of_locked_relevant_machines
                            or updated_number_of_unlocked_relevant_machines < initial_number_of_unlocked_relevant_machines
                        ):
                            break
                        # Relaxxxx
                        time.sleep(self.options.az.scale_down_polling_period)
                        log.debug(
                            f"Scaling {vmss_name} down until new task is received. {number_of_relevant_machines} -> {number_of_relevant_machines_required}"
                        )

                        # Get an updated count of relevant machines
                        relevant_machines = self._get_relevant_machines(tag)
                        number_of_relevant_machines = len(relevant_machines)
                        machine_pools[vmss_name]["size"] = number_of_relevant_machines

                    # No longer scaling down
                    machine_pools[vmss_name]["is_scaling_down"] = False
                    machine_pools[vmss_name]["is_scaling"] = False
                    return
                else:
                    # We only scale down if the relevant task queue is 0
                    machine_pools[vmss_name]["is_scaling"] = False
                    return

            # Update the capacity of the VMSS
            log.debug(f"Scaling {vmss_name} size from {initial_capacity} -> {number_of_relevant_machines_required}")
            vmss = Azure._azure_api_call(
                self.options.az.sandbox_resource_group,
                vmss_name,
                operation=self.compute_client.virtual_machine_scale_sets.get,
            )
            vmss.sku.capacity = number_of_relevant_machines_required
            start_time = timeit.default_timer()

            try:
                Azure._wait_for_concurrent_operations_to_complete()
                current_vmss_operations += 1
                async_update_vmss = Azure._azure_api_call(
                    self.options.az.sandbox_resource_group,
                    vmss_name,
                    vmss,
                    polling_interval=1,
                    operation=self.compute_client.virtual_machine_scale_sets.begin_update,
                )
                _ = self._handle_poller_result(async_update_vmss)
                current_vmss_operations -= 1
            except CuckooMachineError as e:
                current_vmss_operations -= 1
                log.warning(repr(e))
                machine_pools[vmss_name]["wait"] = False
                machine_pools[vmss_name]["is_scaling"] = False
                if platform:
                    is_platform_scaling[platform] = False
                return

            timediff = timeit.default_timer() - start_time
            log.debug(f"The scaling of {vmss_name} took {round(timediff)}s")
            machine_pools[vmss_name]["size"] = number_of_relevant_machines_required

            # Alter the database based on if we scaled up or down
            log.debug(f"Updated {vmss_name} capacity: {number_of_relevant_machines_required}; Initial capacity: {initial_capacity}")
            if number_of_relevant_machines_required > initial_capacity:
                self._add_machines_to_db(vmss_name)
            else:
                self._delete_machines_from_db_if_missing(vmss_name)

            # I release you from your earthly bonds!
            machine_pools[vmss_name]["wait"] = False
            machine_pools[vmss_name]["is_scaling"] = False
            if platform:
                is_platform_scaling[platform] = False
            log.debug(f"Scaling {vmss_name} has completed.")
        except Exception as exc:
            machine_pools[vmss_name]["wait"] = False
            machine_pools[vmss_name]["is_scaling"] = False
            if platform:
                is_platform_scaling[platform] = False
            log.error(repr(exc), exc_info=True)
            log.debug(f"Scaling {vmss_name} has completed with errors {exc!r}.")

    @staticmethod
    def _handle_poller_result(lro_poller_object):
        """
        Provides method of handling Azure tasks that take too long to complete
        @param lro_poller_object: An LRO Poller Object for an Async Azure Task
        """
        start_time = timeit.default_timer()
        # TODO: Azure disregards the timeout passed to it in most cases, unless it has a custom poller
        try:
            lro_poller_result = lro_poller_object.result(timeout=AZURE_TIMEOUT)
        except Exception as e:
            raise CuckooMachineError(repr(e))
        time_taken = timeit.default_timer() - start_time
        if time_taken >= AZURE_TIMEOUT:
            raise CuckooMachineError(f"The task took {round(time_taken)}s to complete! Bad Azure!")
        else:
            return lro_poller_result

    def _get_number_of_relevant_tasks(self, tag, platform=None):
        """
        Returns the number of relevant tasks for a tag or platform
        @param tag: The OS tag used for finding relevant tasks
        @param platform: The platform used for finding relevant tasks
        @return int: The number of relevant tasks for the given tag
        """
        # Getting all tasks in the queue
        tasks = self.db.list_tasks(status=TASK_PENDING)

        # The task queue that will be used to prepare machines will be relative to the virtual
        # machine tag that is targeted in the task (win7, win10, etc) or platform (windows, linux)
        relevant_task_queue = 0

        if not platform:
            for task in tasks:
                for t in task.tags:
                    if t.name == tag:
                        relevant_task_queue += 1
        else:
            for task in tasks:
                if task.platform == platform:
                    relevant_task_queue += 1
        return relevant_task_queue

    def _get_relevant_machines(self, tag):
        """
        Returns the relevant machines for a given tag
        @param tag: The OS tag used for finding relevant machines
        @return list of db.Machine: The machines that are relevant for the given tag
        """
        # The number of relevant machines are those from the list of locked and unlocked machines
        # that have the correct tag in their name
        return [machine for machine in self.db.list_machines() if tag in machine.label]

    @staticmethod
    def _wait_for_concurrent_operations_to_complete():
        """
        Waits until concurrent operations have reached an acceptable level to continue (less than 4)
        """
        start_time = timeit.default_timer()
        while current_vmss_operations == MAX_CONCURRENT_VMSS_OPERATIONS:
            if (timeit.default_timer() - start_time) > AZURE_TIMEOUT:
                log.debug("The timeout has been exceeded for the current concurrent VMSS operations to complete. Unleashing!")
                break
            else:
                time.sleep(1)

    def _thr_reimage_list_reader(self):
        """
        Provides the logic for a list reader thread which performs batch reimaging
        """
        global current_vmss_operations, vms_currently_being_reimaged, reimage_vm_list, delete_vm_list

        while True:
            try:
                time.sleep(5)

                # If no more current vmss operations can be added, then sleep on it!
                if current_vmss_operations == MAX_CONCURRENT_VMSS_OPERATIONS:
                    continue

                with reimage_lock:
                    # If there are no jobs in the reimage_vm_list, then sleep on it!
                    if not reimage_vm_list:
                        continue

                    # Stage 1: Determine from the list of VMs to be reimaged which VMs should be reimaged

                    # Check the time of the first item, which in theory will be the first added
                    if time.time() - reimage_vm_list[0]["time_added"] >= self.options.az.wait_time_to_reimage:
                        # We are processing a batch here not based on biggest size but based on having the oldest reimage job
                        # Now check if there are any other VMs from the same VMSS to reimage
                        vmss_to_reimage = reimage_vm_list[0]["vmss"]
                        vms_to_reimage_from_same_vmss = [vm for vm in reimage_vm_list if vm["vmss"] == vmss_to_reimage]
                    else:
                        # In terms of overall task speed, processing the largest batch will have the greatest impact on processing.
                        # Find the largest batch of VMs from the same VMSS
                        vmss_vm_reimage_counts = {vmss_name: 0 for vmss_name in self.required_vmsss.keys()}
                        for vm in reimage_vm_list:
                            vmss_vm_reimage_counts[vm["vmss"]] += 1
                        max = 0
                        for vmss_name, count in vmss_vm_reimage_counts.items():
                            # The idea here is that even if two VMSSs have the same amount of VMs in the list, then the VMSS
                            # that contains the VM with the oldest reimage request will be selected due to how we are iterating
                            # through the list
                            if count > max:
                                max = count
                                vmss_to_reimage = vmss_name
                        vms_to_reimage_from_same_vmss = [vm for vm in reimage_vm_list if vm["vmss"] == vmss_to_reimage]

                    # Before we remove VMs from the reimage_vm_list, we add to this list
                    for vm in vms_to_reimage_from_same_vmss:
                        vms_currently_being_reimaged.append(f"{vm['vmss']}_{vm['id']}")

                    # Remove VMs we are about to reimage from the global reimage_vm_list
                    for vm in vms_to_reimage_from_same_vmss:
                        reimage_vm_list.remove(vm)

                # Stage 2: Actually performing the batch reimaging
                # The use of sets here is more of a safety for the reimage_all
                instance_ids = list(set([vm["id"] for vm in vms_to_reimage_from_same_vmss]))
                try:
                    Azure._wait_for_concurrent_operations_to_complete()
                    start_time = timeit.default_timer()
                    current_vmss_operations += 1
                    async_reimage_some_machines = Azure._azure_api_call(
                        self.options.az.sandbox_resource_group,
                        vmss_to_reimage,
                        models.VirtualMachineScaleSetVMInstanceIDs(instance_ids=instance_ids),
                        polling_interval=1,
                        operation=self.compute_client.virtual_machine_scale_sets.begin_reimage_all,
                    )
                except Exception as exc:
                    log.error(repr(exc), exc_info=True)
                    # If InvalidParameter: 'The provided instanceId x is not an active Virtual Machine Scale Set VM instanceId.
                    # This means that the machine has been deleted
                    # If BadRequest: The VM x creation in Virtual Machine Scale Set <vmss name>> with ephemeral disk is not complete. Please trigger a restart if required'
                    # This means Azure has failed us
                    instance_ids_that_should_not_be_reimaged_again = set()
                    if "InvalidParameter" in repr(exc) or "BadRequest" in repr(exc):
                        # Parse out the instance ID(s) in this error so we know which instances don't exist
                        instance_ids_that_should_not_be_reimaged_again = {
                            substring for substring in repr(exc).split() if substring.isdigit()
                        }
                    current_vmss_operations -= 1

                    for instance_id in instance_ids_that_should_not_be_reimaged_again:
                        if "InvalidParameter" in repr(exc):
                            log.warning(f"Machine {vmss_to_reimage}_{instance_id} does not exist anymore. Deleting from database.")
                        elif "BadRequest" in repr(exc):
                            log.warning(
                                f"Machine {vmss_to_reimage}_{instance_id} cannot start due to ephemeral disk issues with Azure. Deleting from database and Azure."
                            )
                            with vms_currently_being_deleted_lock:
                                vms_currently_being_deleted.append(f"{vmss_to_reimage}_{instance_id}")
                            with delete_lock:
                                delete_vm_list.append({"vmss": vmss_to_reimage, "id": instance_id, "time_added": time.time()})

                        self.delete_machine(f"{vmss_to_reimage}_{instance_id}", delete_from_vmss=False)
                        vms_currently_being_reimaged.remove(f"{vmss_to_reimage}_{instance_id}")
                        instance_ids.remove(instance_id)

                    with reimage_lock:
                        for instance_id in instance_ids:
                            reimage_vm_list.append({"vmss": vmss_to_reimage, "id": instance_id, "time_added": time.time()})
                            vms_currently_being_reimaged.remove(f"{vmss_to_reimage}_{instance_id}")
                        continue

                # We wait because we want the machine to be fresh before another task is assigned to it
                while not async_reimage_some_machines.done():
                    if (timeit.default_timer() - start_time) > AZURE_TIMEOUT:
                        log.debug(
                            f"Reimaging machines {instance_ids} in {vmss_to_reimage} took too long, deleting them from the DB and the VMSS."
                        )
                        # That sucks, now we have to delete each one
                        for instance_id in instance_ids:
                            self.delete_machine(f"{vmss_to_reimage}_{instance_id}")
                        break
                    time.sleep(2)

                # Clean up
                for vm in vms_to_reimage_from_same_vmss:
                    vm_id = f"{vm['vmss']}_{vm['id']}"
                    if vm_id in vms_currently_being_reimaged:
                        vms_currently_being_reimaged.remove(vm_id)

                current_vmss_operations -= 1
                timediff = timeit.default_timer() - start_time
                log.debug(f"Reimaging instances {instance_ids} in {vmss_to_reimage} took {round(timediff)}s")
            except Exception as e:
                log.error(f"Exception occurred in the reimage thread: {e}. Trying again...")

    def _thr_delete_list_reader(self):
        global current_vmss_operations, delete_vm_list, vms_currently_being_deleted

        while True:
            try:
                time.sleep(5)

                if current_vmss_operations == MAX_CONCURRENT_VMSS_OPERATIONS:
                    continue

                with delete_lock:
                    if not delete_vm_list:
                        continue

                    # Biggest batch only
                    vmss_vm_delete_counts = {vmss_name: 0 for vmss_name in self.required_vmsss.keys()}
                    for vm in delete_vm_list:
                        vmss_vm_delete_counts[vm["vmss"]] += 1
                    max = 0
                    for vmss_name, count in vmss_vm_delete_counts.items():
                        if count > max:
                            max = count
                            vmss_to_delete = vmss_name
                    vms_to_delete_from_same_vmss = [vm for vm in delete_vm_list if vm["vmss"] == vmss_to_delete]

                    for vm in vms_to_delete_from_same_vmss:
                        delete_vm_list.remove(vm)

                instance_ids = list(set([vm["id"] for vm in vms_to_delete_from_same_vmss]))
                try:
                    Azure._wait_for_concurrent_operations_to_complete()
                    start_time = timeit.default_timer()
                    current_vmss_operations += 1
                    async_delete_some_machines = Azure._azure_api_call(
                        self.options.az.sandbox_resource_group,
                        vmss_to_delete,
                        models.VirtualMachineScaleSetVMInstanceIDs(instance_ids=instance_ids),
                        polling_interval=1,
                        operation=self.compute_client.virtual_machine_scale_sets.begin_delete_instances,
                    )
                except Exception as exc:
                    log.error(repr(exc), exc_info=True)
                    current_vmss_operations -= 1
                    with vms_currently_being_deleted_lock:
                        for instance_id in instance_ids:
                            vms_currently_being_deleted.remove(f"{vmss_to_delete}_{instance_id}")
                    continue

                # We wait because we want the machine to be fresh before another task is assigned to it
                while not async_delete_some_machines.done():
                    if (timeit.default_timer() - start_time) > AZURE_TIMEOUT:
                        log.debug(f"Deleting machines {instance_ids} in {vmss_to_delete} took too long.")
                        break
                    time.sleep(2)

                with vms_currently_being_deleted_lock:
                    for instance_id in instance_ids:
                        vms_currently_being_deleted.remove(f"{vmss_to_delete}_{instance_id}")

                current_vmss_operations -= 1
                log.debug(
                    f"Deleting instances {instance_ids} in {vmss_to_delete} took {round(timeit.default_timer() - start_time)}s"
                )
            except Exception as e:
                log.error(f"Exception occurred in the delete thread: {e}. Trying again...")
