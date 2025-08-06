==========================
Installing the Linux guest
==========================

Linux guests doesn't have official CAPAE support!
First, prepare the networking for your machinery platform on the host side.

.. This has not been tested recently:

Sparc and PowerPC dependencies::
    $ sudo apt-get install openbios-sparc openbios-ppc

Next, get the list of virtual machines for which to configure the interface
from ``conf/qemu.conf``.
For example, ``ubuntu_x32``, ``ubuntu_x64``, ``ubuntu_arm``, ``ubuntu_mips``,
``ubuntu_mipsel``, et cetera.
For each VM, preconfigure a network tap interface on the host, required to
avoid having to start as root, e.g.::

    $ sudo ip tuntap add dev tap_ubuntu_x32 mode tap user cape
    $ sudo ip link set tap_ubuntu_x32 master br0
    $ sudo ip link set dev tap_ubuntu_x32 up
    $ sudo ip link set dev br0 up

    $ sudo ip tuntap add dev tap_ubuntu_x64 mode tap user cape
    $ sudo ip link set tap_ubuntu_x64 master br0
    $ sudo ip link set dev tap_ubuntu_x64 up
    $ sudo ip link set dev br0 up

**Note that if you run CAPE as a different user, replace ``cape`` after -u
with your user. You also have a script in utils/linux_mktaps.sh**


Preparing x32/x64 Linux guests
===========================================

    .. warning::

        For Linux guests on an Azure hypervisor, installing Python3 32-bit breaks the way that the Azure agent starts: https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/agent-linux#installation.
        So the use of the monitor is limited to what can be run with the 64-bit version of Python3. You will have to comment out the architecture check in the CAPE `agent.py` for the CAPE agent to start. To
        reiterate, this warning is only relevant if you are using an Azure hypervisor.

x32 guests
----------
Install support file dependencies::

    $ sudo apt update
    $ sudo apt install python3-pip systemtap-runtime
    $ sudo pip3 install pyinotify
    $ sudo pip3 install Pillow       # optional
    $ sudo pip3 install pyscreenshot # optional
    $ sudo pip3 install pyautogui    # optional

x64 guests
----------
Install support file dependencies (we need Python3 32-bit)::

    $ sudo dpkg --add-architecture i386
    $ sudo apt update
    $ sudo apt install python3:i386 -y
    $ sudo apt install python3-distutils -y
    $ sudo apt install systemtap-runtime -y
    $ curl -sSL https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    $ sudo python3 get-pip.py
    $ sudo python3 -m pip install pyinotify
    $ sudo python3 -m pip install Pillow       # optional
    $ sudo python3 -m pip install pyscreenshot # optional
    $ sudo python3 -m pip install pyautogui    # optional

Ensure the agent automatically starts. The easiest way is to add it to crontab::

    $ sudo crontab -e
    @reboot python3 /path/to/agent.py

Disable the firewall inside of the VM, if it exists::

    $ sudo ufw disable

Disable NTP inside of the VM::

    $ sudo timedatectl set-ntp off

Disable auto-update for noise reduction::

    $ sudo tee /etc/apt/apt.conf.d/20auto-upgrades << EOF
    APT::Periodic::Update-Package-Lists "0";
    APT::Periodic::Download-Upgradeable-Packages "0";
    APT::Periodic::AutocleanInterval "0";
    APT::Periodic::Unattended-Upgrade "0";
    EOF

    $ sudo systemctl stop snapd.service && sudo systemctl mask snapd.service

If needed, kill the unattended-upgrade process using ``htop`` or ``ps`` + ``kill``.

Optional - remove preinstalled software and configurations::

    $ sudo apt-get purge update-notifier update-manager update-manager-core ubuntu-release-upgrader-core -y
    $ sudo apt-get purge whoopsie ntpdate cups-daemon avahi-autoipd avahi-daemon avahi-utils -y
    $ sudo apt-get purge account-plugin-salut libnss-mdns telepathy-salut -y

It is recommended to configure the Linux guest with a static IP addresses.
Make sure the machine entry in the configuration has the correct IP address and
has the ``platform`` variable set to ``linux``.
Create a snapshot once the VM has been configured.
It is now ready for analysis!

Community Feature - Tracee
---

*For more information about Tracee in CAPEv2 and how to install it, visit its integration page: :ref:`tracee`.*

To use [Tracee eBPF event tracing](https://github.com/kevoreilly/CAPEv2/pull/2235) in Linux, you will have to install Docker and the Tracee container **in the Ubuntu guest**:

```shell
docker pull docker.io/aquasec/tracee:0.20.0
docker image tag aquasec/tracee:0.20.0 aquasec/tracee:latest
```

Afterwards, enable Tracee using the appropriate options in auxiliary.conf and processing.conf and install the [CAPEv2 Community Repo](https://github.com/CAPESandbox/community). Here is a guide: https://capev2.readthedocs.io/en/latest/usage/utilities.html#community-download-utility.

Tracee should be able to automatically highlight events such as fileless execution and syscall hooking.
