import argparse
import ipaddress
import os
import subprocess
import tempfile
from time import sleep
from typing import List, NamedTuple
from xml.dom.minidom import parseString

import randmac
import tqdm

NETWORK_NAME = "default"
DEFAULT_STORAGE = "/data/vms/"
SLEEP_TIME = 650
DEFAULT_SNAPSHOT_NAME = "clean"


class Machine(NamedTuple):
    number: int
    name: str
    ip: str
    mac_address: str
    hd_path: str


def setup_network(machines: List[Machine], is_dry_run: bool = False):
    # dump current network
    print("--- Modifying virsh network ----")
    network_xml = _run_virsh_command(["net-dumpxml", NETWORK_NAME], capture_output=True)
    network_doc = parseString(network_xml.stdout)

    dhcp_node = network_doc.documentElement.getElementsByTagName("ip")[0].getElementsByTagName("dhcp")[0]

    for machine in machines:
        curr_host_node = network_doc.createElement("host")
        curr_host_node.setAttribute("mac", machine.mac_address)
        curr_host_node.setAttribute("name", machine.name)
        curr_host_node.setAttribute("ip", machine.ip)

        dhcp_node.appendChild(curr_host_node)

    print("New network xml definition:")
    print(network_doc.toxml())

    if not is_dry_run:
        with tempfile.NamedTemporaryFile(mode="w") as temp_file:
            network_doc.writexml(temp_file)
            temp_file.flush()

            # update network
            _run_virsh_command(["net-define", temp_file.name])

            print("Network defined, restarting it")
            _run_virsh_command(["net-destroy", NETWORK_NAME])
            _run_virsh_command(["net-start", NETWORK_NAME])


def create_machine_snapshot(machine: Machine):
    print(f"Creating new snapshot for {machine.name}")
    _run_virsh_command(["snapshot-create-as", machine.name, DEFAULT_SNAPSHOT_NAME])


# region helpers


def _run_virsh_command(args: List[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["virsh", *args], **kwargs)


def _start_machine(machine_name: str):
    _run_virsh_command(["start", machine_name])


def _stop_machine(machine_name: str):
    _run_virsh_command(["shutdown", machine_name])


# endregion helpers


def init_machines(machines: List[Machine]):
    # start all machines
    for machine in machines:
        _start_machine(machine.name)

    # sleep?
    for i in tqdm.tqdm(range(SLEEP_TIME), desc="Sleeping ... ZzzZZzz", total=SLEEP_TIME):
        sleep(1)

    for machine in machines:
        create_machine_snapshot(machine)
        _stop_machine(machine.name)


def clone_machines(
    original_machine_name: str,
    original_machine_hd_path: str,
    machine_name_format: str,
    machine_hd_path: str,
    number_of_machine: int,
    machine_start_from: int,
    starting_ip: ipaddress.IPv4Address,
    is_dry_run: bool = False,
) -> List[Machine]:
    machines = []
    current_ip = starting_ip

    for machine_num in range(number_of_machine):
        machine_id = machine_start_from + machine_num
        machine_name = machine_name_format.format(machine_id)

        curr_machine = Machine(
            machine_id,
            machine_name,
            str(current_ip),
            str(randmac.RandMac()),
            os.path.join(machine_hd_path, f"{machine_name}.qcow2"),
        )

        print("Creating new machine:")
        print(curr_machine)

        print("cloning using virt-clone")
        if is_dry_run:
            print(f"copy the disk file. {original_machine_hd_path} -> {curr_machine.hd_path}")
        else:
            output = subprocess.run(
                [
                    "virt-clone",
                    "--original",
                    original_machine_name,
                    "--name",
                    curr_machine.name,
                    "--mac",
                    curr_machine.mac_address,
                    "--file",
                    curr_machine.hd_path,
                ]
            )

            if output.returncode != 0:
                print("there was an error cloning the machine, continuing")
                continue
        machines.append(curr_machine)

        # set next IP
        current_ip += 1

    return machines


def print_machines_config(machines):
    print("Please add these new machines to the appropriate config file (also in ./machines.conf):")

    with open("machines.conf", "w") as machines_file:
        for machine in machines:
            machine_lines_str = "\n".join(
                [
                    f"[{machine.name}]",
                    f"label = {machine.name}",
                    "platform = windows",
                    f"ip = {machine.ip}",
                    "tags = x64",
                    f"snapshot = {DEFAULT_SNAPSHOT_NAME}",
                    "arch = x64",
                ]
            )

            machines_file.write(machine_lines_str + "\n\n")
            print(machine_lines_str + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Machine Cloner",
        description="Use this util to clone guest machine - including modifying the network & ips and creating snapshots",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true", help="doesnt actually change anything")

    parser.add_argument("--original", type=str, required=True, help="Original machine to clone name")
    parser.add_argument(
        "--original-disk", type=str, required=True, default=DEFAULT_STORAGE, help="Original machine to clone full path to disk"
    )

    parser.add_argument("--prefix", type=str, default="machine", help="prefix to new machine name")
    parser.add_argument(
        "--storage-path",
        type=str,
        default=DEFAULT_STORAGE,
        help="Path to the directory where all the new machines disk will be saved. (default",
    )

    parser.add_argument("--count", type=int, default=1, help="How many machine should be created")
    parser.add_argument("--count-offset", type=int, default=1, help="At what number should the count start")

    parser.add_argument("--ip", type=str, required=True, help="The base IP address machines should start to be created")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation")
    args = parser.parse_args()

    # Handle arguments
    original_machine_name = args.original
    original_machine_disk = args.original_disk

    if not os.path.exists(original_machine_disk):
        raise ValueError("Original disk file is missing!")

    machine_hd_dir = args.storage_path
    if not os.path.exists(machine_hd_dir):
        raise ValueError("VMs Storage dir doesnt exists")

    machine_name_format = f"{args.prefix}-{{}}"

    number_of_machines = args.count
    start_machine = args.count_offset
    starting_ip = ipaddress.ip_address(args.ip)

    is_dry_run = args.dry_run

    # prompt
    print("Please confirm this configurations:")

    print(f"Original machine name: {args.original}")
    print(f"Original machine disk: {original_machine_disk}")
    print("")
    print(f"New machines name formatting: {machine_name_format}")
    print(f"New machines disk dir: {machine_hd_dir}")
    print("------")
    print(f"Number of machines: {number_of_machines}")
    print(f"Start from machine: {start_machine}")
    print("------")
    print(f"Start at IP address: {starting_ip}")
    print("")
    print("** Not a dry run! **") if not is_dry_run else print("-- dry run --")

    if not args.yes:
        user_input = input("Please type [yes/y] to config: ")
        if user_input.lower() not in ("y", "yes"):
            raise ValueError("Please confirm the configurations!")

    machines = clone_machines(
        args.original,
        original_machine_disk,
        machine_name_format,
        machine_hd_dir,
        number_of_machines,
        start_machine,
        starting_ip,
        is_dry_run,
    )

    if not machines:
        raise RuntimeError("No machines were created...")

    print()
    setup_network(machines, is_dry_run)

    print()
    if is_dry_run:
        print("Dry Run: not initalizing machines...")
    else:
        init_machines(machines)

    print()
    print_machines_config(machines)

# sudo python3 clone-machines.py --dry-run --original win7-v4-clean --original-disk /data/vms/win7-v4-clean.qcow2 --prefix win7-v4 --count 1 --count-offset 10 --ip 192.168.1.186
