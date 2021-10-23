# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# https://qemu.readthedocs.io/en/latest/

from __future__ import absolute_import
import os
import time
import magic
import logging
import subprocess
import os.path

# from lib.cuckoo.core.rooter import rooter
from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)
cfg = Config()
qemu_cfg = Config("qemu")

# os.listdir('/sys/class/net/')
HAVE_NETWORKIFACES = False
try:
    import psutil
    network_interfaces = list(psutil.net_if_addrs().keys())
    HAVE_NETWORKIFACES = True
except ImportError:
    print("Missde dependency: pip3 install psutil")


# this whole semi-hardcoded commandline thing is not the best
#  but in the config files we can't do arrays etc so we'd have to parse the
#  configured commandlines somehow and then fill in some more things
#  anyways, if someone has a cleaner suggestion for this, let me know
#  -> for now, just modify this to your needs
QEMU_ARGS = {
    "default": {
        "cmdline": ["qemu-system-x86_64", "-display", "none"],
        "params": {
            "memory": "512M",
            "mac": "52:54:00:12:34:56",
            "kernel": "{imagepath}/vmlinuz",
        },
    },
    "mipsel": {
        "cmdline": [
            "qemu-system-mipsel",
            "-display", "none",
            "-M","malta",
            "-m", "{memory}",
            "-kernel", "{kernel}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1 console=tty0",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",  # virtio-net-pci doesn't work here
        ],
        "params": {
            "kernel": "{imagepath}/vmlinux-4.19.0-8-4kc-malta-mipsel",
        }
    },
    "mips": {
        "cmdline": [
            "qemu-system-mips", "-display", "none",
            "-M", "malta", "-m", "{memory}",
            "-kernel", "{kernel}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1 console=ttyS0 nokaslr",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",
        ],
        "params": {
            "kernel": "{imagepath}/vmlinux-4.19.0-8-4kc-malta",
            "machine": "",
        }
    },
    "armwrt": {
        "cmdline": [
            "qemu-system-arm", "-display", "none",
            "-M", "realview-eb-mpcore", "-m", "{memory}",
            "-kernel", "{kernel}",
            "-drive", "if=sd,cache=unsafe,file={snapshot_path}",
            "-append", "console=ttyAMA0 root=/dev/mmcblk0 rootwait",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "virtio-net-device,netdev=net_{vmname},mac={mac}",
        ],
        "params": {
            "kernel": "{imagepath}/openwrt-realview-vmlinux.elf",
        }
    },
    "arm": {
        "cmdline": [
            "qemu-system-arm", "-display", "none",
            "-M", "virt", "-m", "{memory}",
            "-kernel", "{kernel}", "-initrd", "{initrd}",
            "-drive", "if=none,file={snapshot_path},id=hd0",
            "-device", "virtio-blk-device,drive=hd0",
            "-append", "root=/dev/vda2",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "virtio-net-device,netdev=net_{vmname},mac={mac}",
        ],
        "params": {
            "memory": "{memory}",
            "kernel": "{imagepath}/vmlinuz-3.2.0-4-versatile-arm",
            "initrd": "{imagepath}/initrd-3.2.0-4-versatile-arm",
        }
    },
    "arm64": {
        "cmdline": [
            "qemu-system-aarch64",
            "-display", "none",
            "-M", "virt", "-m", "{memory}",
            "-kernel", "{kernel}", "-initrd", "{initrd}",
            "-drive", "if=none,file={snapshot_path},id=hd0",
            "-device", "virtio-blk-device,drive=hd0",
            "-append", "root=/dev/sda1",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "virtio-net-device,netdev=net_{vmname},mac={mac}",
        ],
        "params": {
            "memory": "512M",  # 512 didn't work for some reason
            "kernel": "{imagepath}/vmlinuz-3.2.0-4-versatile-arm",
            "initrd": "{imagepath}/initrd-3.2.0-4-versatile-arm",
        }
    },
    "x64": {
        "cmdline": [
            "qemu-system-x86_64",
            "-display", "none",
            "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",
        ],
        "params": {
            "memory": "1024M",
        }
    },
    "x86": {
        "cmdline": [
            "qemu-system-i386",
            "-display", "none",
            "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",
        ],
        "params": {
            "memory": "1024M",
        }
    },
    "powerpc": {
         "cmdline": [
            "qemu-system-ppc",
            "-display", "none",
            "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",
         ],
         "params": {
            "memory": "256M",
            "machine": "none",
         }
    },
    "powerpc64": {
         "cmdline": [
            "qemu-system-ppc64",
            "-display", "none",
            "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",
         ],
         "params": {
             "memory": "512M",
         }
    },
    "sh4": {
         "cmdline": [
            "qemu-system-sh4",
            "-display", "none",
            "-M", "r2d", "-m", "{memory}",
            "-kernel", "{kernel}", "-initrd", "{initrd}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1 noiotrap",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",  # virtio-net-pci doesn't work here
         ],
        "params": {
            "memory": "64M",
            "kernel": "{imagepath}/vmlinuz-2.6.32-5-sh7751r",
            "initrd": "{imagepath}/initrd.img-2.6.32-5-sh7751r",
        }
    },
    "sparc": {
         "cmdline": [
            "qemu-system-sparc",
            "-display", "none",
            "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",  # virtio-net-pci doesn't work here
        ],
        "params": {
            "memory": "256M",
        }
    },
    "sparc64": {
         "cmdline": [
            "qemu-system-sparc64",
            "-display", "none",
            "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",  # virtio-net-pci doesn't work here
        ],
        "params": {
            "memory": "256M",
        }
    },
}


class QEMU(Machinery):
    """Virtualization layer for QEMU (non-KVM)."""

    # VM states.
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "machete"

    def __init__(self):
        super(QEMU, self).__init__()
        self.state = {}

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if QEMU binary is not found.
        """
        # VirtualBox specific checks.
        if not self.options.qemu.path:
            raise CuckooCriticalError("QEMU binary path missing, please add it to the config file")
        if not os.path.exists(self.options.qemu.path):
            raise CuckooCriticalError("QEMU binary not found at specified path \"%s\"" % self.options.qemu.path)

        self.qemu_dir = os.path.dirname(self.options.qemu.path)
        self.qemu_img = os.path.join(self.qemu_dir, "qemu-img")
        # 1 check if arch is not x32 or x64
        # 2 check for kernel and initrd files
        # 3 check for snapshot
        # 3. check tap device

        for vm_label in qemu_cfg.qemu.machines.split(","):
            try:
                vm_config = qemu_cfg.get(vm_label.strip())
                if vm_config.get("platform", "").strip() != "linux":
                    continue
                if vm_config.get("image", False) and not os.path.exists(vm_config["image"]):
                    log.error(f"Missed harddrive file for VM: {vm_label}")
                if vm_config.get("kernel", False) and not magic.from_file(vm_config['kernel']).startswith(("Linux kernel", "ELF")):
                    log.error(f"Bad Kernel file for VM: {vm_label} - {vm_config['kernel']}")
                if vm_config.get("initrd", False) and not magic.from_file(vm_config['initrd']).startswith("gzip"):
                    log.error(f"Bad initrd file for VM: {vm_label} - {vm_config['initrd']}")
                if vm_config.get("snapshot", False) and vm_config.get("image", False):
                    try:
                        snalshot_list = subprocess.check_output([self.qemu_img, "snapshot", "-l", vm_config["image"]], universal_newlines=True)
                        if vm_config["snapshot"] not in snalshot_list:
                            log.error(f"Snapshot: {vm_config['snapshot']} doesn't exist for VM: {vm_label}")
                    except Exception as e:
                        log.debug(f"Can't check snapshot list for VM:{vm_label} - {e}")

                if vm_config.get("interface", False) and HAVE_NETWORKIFACES and vm_config["interface"] not in network_interfaces:
                    log.error(f"Missed TAP network interface {vm_config['interface']}")
            except Exception as e:
                log.exception(e)

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        vm_info = self.db.view_machine_by_label(label)
        vm_options = getattr(self.options, vm_info.name)

        if vm_options.snapshot:
            snapshot_path = vm_options.image
        else:
            snapshot_path = os.path.join(
                os.path.dirname(vm_options.image),
                "snapshot_%s.qcow2" % vm_info.name
            )
            if os.path.exists(snapshot_path):
                os.remove(snapshot_path)

            # make sure we use a new harddisk layer by creating a new qcow2 with backing file
            # https://qemu.readthedocs.io/en/latest/about/removed-features.html?highlight=backing#qemu-img-backing-file-without-format-removed-in-6-1
            try:
                proc = subprocess.Popen([
                    self.qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", vm_options.image, snapshot_path
                ], universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, err = proc.communicate()
                if err:
                    raise OSError(err)
            except OSError as e:
                raise CuckooMachineError(
                    "QEMU failed starting the machine: %s" % e
                )

        vm_arch = getattr(vm_options, "arch", "default")
        arch_config = dict(QEMU_ARGS[vm_arch])
        cmdline = arch_config["cmdline"]
        params = dict(QEMU_ARGS["default"]["params"])
        params.update(QEMU_ARGS[vm_arch]["params"])

        params.update({
            "imagepath": os.path.dirname(vm_options.image),
            "snapshot_path": snapshot_path,
            "vmname": vm_info.name,
            "memory": vm_options.memory,
        })

        # allow some overrides from the vm specific options
        # also do another round of parameter formatting
        for var in ["mac", "kernel", "initrd"]:
            val = getattr(vm_options, var, params.get(var, None))
            if not val:
                continue
            params[var] = val.format(**params)

        # magic arg building
        final_cmdline = [i.format(**params) for i in cmdline]

        if vm_options.snapshot:
            final_cmdline += ["-loadvm", vm_options.snapshot]

        if vm_options.enable_kvm:
            final_cmdline.append("-enable-kvm")

        if hasattr(vm_options, "cpu") and vm_options.cpu:
            final_cmdline += ["-cpu", vm_options.cpu]

        log.debug("Executing QEMU %r", final_cmdline)

        try:
            proc = subprocess.Popen(
                final_cmdline,  universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.state[vm_info.name] = proc
        except OSError as e:
            raise CuckooMachineError("QEMU failed starting the machine: %s" % e)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug(f"Stopping vm {label}")

        vm_info = self.db.view_machine_by_label(label)

        if self._status(vm_info.name) == self.STOPPED:
            raise CuckooMachineError(f"Trying to stop an already stopped vm {label}")

        proc = self.state.get(vm_info.name, None)
        proc.kill()

        stop_me = 0
        while proc.poll() is None:
            if stop_me < cfg.timeouts.vm_state:
                time.sleep(1)
                stop_me += 1
            else:
                log.debug(f"Stopping vm {label} timeouted. Killing")
                proc.terminate()
                time.sleep(1)

        # if proc.returncode != 0 and stop_me < cfg.timeouts.vm_state:
        #     log.debug("QEMU exited with error powering off the machine")

        self.state[vm_info.name] = None

    def _status(self, name):
        """Gets current status of a vm.
        @param name: virtual machine name.
        @return: status string.
        """
        p = self.state.get(name, None)
        if p is not None:
            return self.RUNNING
        return self.STOPPED
