import logging
import sys
import time

try:
    import boto3
except ImportError:
    sys.exit("Missed boto3 dependency: pip3 install boto3")

from sqlalchemy.exc import SQLAlchemyError

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooMachineError

logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
log = logging.getLogger(__name__)


class AWS(Machinery):
    """Virtualization layer for AWS."""

    # VM states.
    PENDING = "pending"
    STOPPING = "stopping"
    RUNNING = "running"
    POWEROFF = "poweroff"
    ERROR = "machete"

    AUTOSCALE_CUCKOO = "AUTOSCALE_CUCKOO"

    def __init__(self):
        super(AWS, self).__init__()

    """override Machinery method"""

    def _initialize_check(self):
        """
        Looking for all EC2 machines that match aws.conf and load them into EC2_MACHINES dictionary.
        """
        self.ec2_machines = {}
        self.dynamic_machines_sequence = 0
        self.dynamic_machines_count = 0
        log.info("connecting to AWS:{}".format(self.options.aws.region_name))
        self.ec2_resource = boto3.resource(
            "ec2",
            region_name=self.options.aws.region_name,
            aws_access_key_id=self.options.aws.aws_access_key_id,
            aws_secret_access_key=self.options.aws.aws_secret_access_key,
        )

        # Iterate over all instances with tag that has a key of AUTOSCALE_CUCKOO
        for instance in self.ec2_resource.instances.filter(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": ["running", "stopped", "stopping"],
                }
            ]
        ):
            if self._is_autoscaled(instance):
                log.info("Terminating autoscaled instance %s" % instance.id)
                instance.terminate()

        instance_ids = self._list()
        machines = self.machines()
        for machine in machines:
            if machine.label not in instance_ids:
                continue
            self.ec2_machines[machine.label] = self.ec2_resource.Instance(machine.label)
            if self._status(machine.label) != AWS.POWEROFF:
                self.stop(label=machine.label)

        self._start_or_create_machines()

    def _start_next_machines(self, num_of_machines_to_start):
        """
        pull from DB the next machines in queue and starts them
        the whole idea is to prepare x machines on, so once a task will arrive - the machine will be ready with windows
        already launched.
        :param num_of_machines_to_start: how many machines(first in queue) will be started
        """
        for machine in self.db.get_available_machines():
            if num_of_machines_to_start <= 0:
                break
            if self._status(machine.label) in (AWS.POWEROFF, AWS.STOPPING):
                self.ec2_machines[machine.label].start()  # not using self.start() to avoid _wait_ method
                num_of_machines_to_start -= 1

    def _delete_machine_form_db(self, label):
        """
        cuckoo's DB class does not implement machine deletion, so we made one here
        :param label: the machine label
        """
        session = self.db.Session()
        try:
            from lib.cuckoo.core.database import Machine

            machine = session.query(Machine).filter_by(label=label).first()
            if machine:
                session.delete(machine)
                session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error removing machine: {0}".format(e))
            session.rollback()
            return
        finally:
            session.close()

    def _allocate_new_machine(self):
        """
        allocating/creating new EC2 instance(autoscale option)
        """
        # read configuration file
        machinery_options = self.options.get("aws")
        autoscale_options = self.options.get("autoscale")
        # If configured, use specific network interface for this
        # machine, else use the default value.
        interface = autoscale_options["interface"] if autoscale_options.get("interface") else machinery_options.get("interface")
        resultserver_ip = (
            autoscale_options["resultserver_ip"] if autoscale_options.get("resultserver_ip") else Config("cuckoo:resultserver:ip")
        )
        if autoscale_options.get("resultserver_port"):
            resultserver_port = autoscale_options["resultserver_port"]
        else:
            # The ResultServer port might have been dynamically changed,
            # get it from the ResultServer singleton. Also avoid import
            # recursion issues by importing ResultServer here.
            from lib.cuckoo.core.resultserver import ResultServer

            resultserver_port = ResultServer().port

        log.info("All machines are busy, allocating new machine")
        self.dynamic_machines_sequence += 1
        self.dynamic_machines_count += 1
        new_machine_name = "cuckoo_autoscale_%03d" % self.dynamic_machines_sequence

        instance = self._create_instance(
            tags=[
                {"Key": "Name", "Value": new_machine_name},
                {"Key": self.AUTOSCALE_CUCKOO, "Value": "True"},
            ]
        )
        attempts = 0
        while attempts < 30:
            try:
                time.sleep(2)
                self.ec2_machines[instance.id] = instance
                #  sets "new_machine" object in configuration object to avoid raising an exception
                setattr(self.options, new_machine_name, {})
                # add machine to DB
                self.db.add_machine(
                    name=new_machine_name,
                    label=instance.id,
                    ip=instance.private_ip_address,
                    arch=autoscale_options["arch"],
                    platform=autoscale_options["platform"],
                    tags=autoscale_options["tags"],
                    interface=interface,
                    snapshot=None,
                    resultserver_ip=resultserver_ip,
                    resultserver_port=resultserver_port,
                    reserved=False,
                )
                break
            except Exception as e:
                attempts += 1
                log.warning(f"Failed while creating new instance {e}. Trying again.")
                instance = None

        if instance is None:
            return False

        return True

    """override Machinery method"""

    def acquire(self, machine_id=None, platform=None, tags=None, need_scheduled=False):
        """
        override Machinery method to utilize the auto scale option
        """
        base_class_return_value = super(AWS, self).acquire(machine_id, platform, tags, need_scheduled=need_scheduled)
        self._start_or_create_machines()  # prepare another machine
        return base_class_return_value

    def _start_or_create_machines(self):
        """
        checks if x(according to "gap" in aws config) machines can be immediately started.
        If autoscale is enabled and less then x can be started - > create new instances to complete the gap
        :return:
        """

        # read configuration file
        machinery_options = self.options.get("aws")
        autoscale_options = self.options.get("autoscale")

        current_available_machines = self.db.count_machines_available()
        running_machines_gap = machinery_options.get("running_machines_gap", 0)
        dynamic_machines_limit = autoscale_options["dynamic_machines_limit"]

        self._start_next_machines(num_of_machines_to_start=min(current_available_machines, running_machines_gap))
        #  if no sufficient machines left  -> launch a new machines
        while autoscale_options["autoscale"] and current_available_machines < running_machines_gap:
            if self.dynamic_machines_count >= dynamic_machines_limit:
                log.debug("Reached dynamic machines limit - %d machines" % dynamic_machines_limit)
                break
            if not self._allocate_new_machine():
                break
            current_available_machines += 1

    """override Machinery method"""

    def _list(self):
        """
        :return: A list of all instance ids under the AWS account
        """
        instances = self.ec2_resource.instances.filter(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": ["running", "stopped", "stopping"],
                }
            ]
        )
        return [instance.id for instance in instances]

    """override Machinery method"""

    def _status(self, label):
        """
        Gets current status of a vm.
        @param label: virtual machine label.
        @return: status string.
        """
        try:
            self.ec2_machines[label].reload()
            state = self.ec2_machines[label].state["Name"]
            if state == "running":
                status = AWS.RUNNING
            elif state == "stopped":
                status = AWS.POWEROFF
            elif state == "pending":
                status = AWS.PENDING
            elif state == "stopping":
                status = AWS.STOPPING
            elif state in ("shutting-down", "terminated"):
                status = AWS.ERROR
            else:
                status = AWS.ERROR
            log.info("instance state: {}".format(status))
            return status
        except Exception as e:
            log.exception("can't retrieve the status: {}".format(e))
            return AWS.ERROR

    """override Machinery method"""

    def start(self, label):
        """
        Start a virtual machine.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm {}".format(label))

        if not self._is_autoscaled(self.ec2_machines[label]):
            self.ec2_machines[label].start()
            self._wait_status(label, AWS.RUNNING)

    """override Machinery method"""

    def stop(self, label):
        """
        Stops a virtual machine.
        If the machine has initialized from autoscaled component, then terminate it.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)

        status = self._status(label)

        if status == AWS.POWEROFF:
            raise CuckooMachineError("Trying to stop an already stopped VM: %s" % label)

        if self._is_autoscaled(self.ec2_machines[label]):
            self.ec2_machines[label].terminate()
            self._delete_machine_form_db(label)
            self.dynamic_machines_count -= 1
        else:
            self.ec2_machines[label].stop(Force=True)
            self._wait_status(label, AWS.POWEROFF)
            self._restore(label)

    """override Machinery method"""

    def release(self, label=None):
        """
        we override it to have the ability to run start_or_create_machines() after unlocking the last machine
        Release a machine.
        @param label: machine label.
        """
        super(AWS, self).release(label)
        self._start_or_create_machines()

    def _create_instance(self, tags):
        """
        create a new instance
        :param tags: tags to attach to instance
        :return: the instance id
        """

        autoscale_options = self.options.get("autoscale")
        response = self.ec2_resource.create_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {"DeleteOnTermination": True, "VolumeType": "gp2"},
                }
            ],
            ImageId=autoscale_options["image_id"],
            InstanceType=autoscale_options["instance_type"],
            MaxCount=1,
            MinCount=1,
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": autoscale_options["subnet_id"],
                    "Groups": autoscale_options["security_groups"].split(","),
                }
            ],
            TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
        )
        new_instance = response[0]
        attempts = 0
        while attempts < 30:
            time.sleep(2)
            try:
                new_instance.modify_attribute(SourceDestCheck={"Value": False})
                break
            except Exception:
                attempts += 1
                log.warning("Failed while modifying new instance attribute. Trying again.")
        log.debug("Created %s\n%s", new_instance.id, repr(response))
        return new_instance

    def _is_autoscaled(self, instance):
        """
        checks if the instance has a tag that indicates that it was created as a result of autoscaling
        :param instance: instance object
        :return: true if the instance in "autoscaled"
        """
        if instance.tags:
            for tag in instance.tags:
                if tag.get("Key") == self.AUTOSCALE_CUCKOO:
                    return True
        return False

    def _restore(self, label):
        """
        restore the instance according to the configured snapshot(aws.conf)
        This method detaches and deletes the current volume, then creates a new one and attaches it.
        :param label: machine label
        """
        log.info("restoring machine: {}".format(label))
        vm_info = self.db.view_machine_by_label(label)
        snap_id = vm_info.snapshot
        instance = self.ec2_machines[label]
        state = self._status(label)
        if state != AWS.POWEROFF:
            raise CuckooMachineError("Instance '%s' state '%s' is not poweroff" % (label, state))
        volumes = list(instance.volumes.all())
        if len(volumes) != 1:
            raise CuckooMachineError("Instance '%s' has wrong number of volumes %d" % (label, len(volumes)))
        old_volume = volumes[0]

        log.debug("Detaching %s", old_volume.id)
        resp = instance.detach_volume(VolumeId=old_volume.id, Force=True)
        log.debug("response: {}".format(resp))
        while True:
            old_volume.reload()
            if old_volume.state != "in-use":
                break
            time.sleep(1)

        log.debug("Old volume %s in state %s", old_volume.id, old_volume.state)
        if old_volume.state != "available":
            raise CuckooMachineError("Old volume turned into state %s instead of 'available'" % old_volume.state)
        log.debug("Deleting old volume")
        volume_type = old_volume.volume_type
        old_volume.delete()

        log.debug("Creating new volume")
        new_volume = self.ec2_resource.create_volume(
            SnapshotId=snap_id,
            AvailabilityZone=instance.placement["AvailabilityZone"],
            VolumeType=volume_type,
        )
        log.debug("Created new volume %s", new_volume.id)
        while True:
            new_volume.reload()
            if new_volume.state != "creating":
                break
            time.sleep(1)
        log.debug("new volume %s in state %s", new_volume.id, new_volume.state)
        if new_volume.state != "available":
            state = new_volume.state
            new_volume.delete()
            raise CuckooMachineError("New volume turned into state %s instead of 'available'" % state)

        log.debug("Attaching new volume")
        resp = instance.attach_volume(VolumeId=new_volume.id, Device="/dev/sda1")
        log.debug("response {}".format(resp))
        while True:
            new_volume.reload()
            if new_volume.state != "available":
                break
            time.sleep(1)
        log.debug("new volume %s in state %s", new_volume.id, new_volume.state)
        if new_volume.state != "in-use":
            new_volume.delete()
            raise CuckooMachineError("New volume turned into state %s instead of 'in-use'" % old_volume.state)
