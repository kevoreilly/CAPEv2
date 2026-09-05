==========================
Installing the Linux guest
==========================

Linux guests don't have official CAPE support!
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


Preparing Linux guests (32-bit & 64-bit)
========================================

Historically, Windows-focused sandbox tools required 32-bit Python runtimes. However, for Linux guests in CAPEv2, **using 32-bit Python on a 64-bit system is not required and is highly discouraged.**

Attempting to force-install 32-bit Python (via ``dpkg --add-architecture i386`` and ``apt install python3:i386``) on a 64-bit Linux guest (e.g., Ubuntu x86_64) will swap out the native 64-bit system Python. This conflicts with core system packages and breaks the operating system, making it impossible to boot the graphical desktop/UI interface (e.g., GNOME/GDM) or use standard system utilities.

For all modern 64-bit (x86_64) Linux guests, you should use the native, standard 64-bit Python 3.

.. note::
    Starting with Python 3.12 (default on Ubuntu 24.04 LTS and later), ``distutils`` has been completely removed from the standard library. The package ``python3-distutils`` is no longer available in package repositories and is not required by CAPEv2's guest agent or Linux analyzer. If any of your custom scripts require it, you can install ``python3-setuptools`` instead.

.. note::
    On newer Linux distributions (Debian 12+, Ubuntu 23.04+), PIP blocks system-wide package installations by default under PEP 668 to avoid corrupting OS packages. Since the guest VM is a disposable sandbox environment, you can safely bypass this warning using the ``--break-system-packages`` flag.

32-bit (i386) guests
--------------------
Install support file dependencies using native 32-bit packages::

    $ sudo apt update
    $ sudo apt install python3-pip systemtap-runtime -y
    $ sudo pip3 install pyinotify Pillow pyscreenshot pyautogui --break-system-packages

64-bit (x86_64 / amd64) guests
------------------------------
Install support file dependencies using standard native 64-bit packages::

    $ sudo apt update
    $ sudo apt install python3 python3-pip systemtap-runtime -y
    $ sudo pip3 install pyinotify Pillow pyscreenshot pyautogui --break-system-packages

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
