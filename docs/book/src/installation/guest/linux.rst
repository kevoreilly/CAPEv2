=========================
Installing the Linux host
=========================

First prepare the networking for your machinery platform on the host side.

.. This has not been tested recently:

Sparc and PowerPC dependencies::
    $ sudo apt-get install openbios-spark openbios-ppc

Next, get the list of virtual machines for which to configure the interface
from ``conf/qemu.conf``.
For example, ``ubuntu_x32``, ``ubuntu_x64``, ``ubuntu_arm``, ``ubuntu_mips``,
``ubuntu_mipsel``, et cetera.
For each VM, preconfigure a network tap interfaces on the host, required to
avoid have to start as root, e.g.::

    $ sudo ip tuntap add dev tap_ubuntu_x32 mode tap user cape
    $ sudo ip link set tap_ubuntu_x32 master br0
    $ sudo ip link set dev tap_ubuntu_x32 up
    $ sudo ip link set dev br0 up

    $ sudo ip tuntap add dev tap_ubuntu_x64 mode tap user cape
    $ sudo ip link set tap_ubuntu_x64 master br0
    $ sudo ip link set dev tap_ubuntu_x64 up
    $ sudo ip link set dev br0 up

**Note that if you run CAPE as a different user, replace ``cape`` after -u
with your user. You also have script in utils/linux_mktaps.sh**


Preparing x32/x64 Linux guests
===========================================

Install support files dependencies::

    $ sudo apt update
    $ sudo apt install python3-pip
    $ pip3 install pyinotify
    $ pip3 install pillow       # optional
    $ pip3 install pyscreenshot # optional

(For x64 architectures) Install python3 32 bits::

    $ sudo dpkg --add-architecture i386
    $ sudo apt update
    $ sudo apt install python3:i386

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

If needed, kill the unattended-upgrade process using htop or ps + kill.

Optional - preinstalled remove software and configurations::

    $ sudo apt-get purge update-notifier update-manager update-manager-core ubuntu-release-upgrader-core
    $ sudo apt-get purge whoopsie ntpdate cups-daemon avahi-autoipd avahi-daemon avahi-utils
    $ sudo apt-get purge account-plugin-salut libnss-mdns telepathy-salut

It is recommended to configure the Linux guest with a static IP addresses.
Make sure the machine entry in the configuration has the correct IP address and
has the ``platform`` variable set to ``linux``.
Create a snapshot once the VM has been configured.
It is now ready for analysis!
