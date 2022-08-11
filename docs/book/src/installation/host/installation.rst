=================
Installing CAPE
=================

Proceed with download and installation. Read :doc:`../../introduction/what` to
learn where you can obtain a copy of the sandbox.

Automated installation, read the full page before you start
===========================================================

We have automated all work for you, but bear in mind, that 3rd party dependencies change frequently and can break the installation,
so please check the installation log and try to provide the fix / correct issue to the developers.

To install CAPE
================

The script to install CAPE can be found here: `cape2.sh`_.

.. _`cape2.sh`: https://github.com/kevoreilly/CAPEv2/blob/master/installer/cape2.sh

You need to give execution permission to script `chmod a+x cape2.sh`. Please keep in mind that all our scripts use the ``-h`` flag to print the help and usage message. However, it is recommended to read the scripts themselves to **understand** what they do.

Please become familiar with available options using::

    $ ./cape2.sh -h

To install CAPE with all the optimization, use the following command.::

    $ sudo ./cape2.sh base cape | tee cape.log

Remember to **reboot** after the installation.

This should install all libraries and services for you, read the code if you need more details. Specifically, the installed services are:

* cape.service
* cape-processor.service
* cape-web.service
* cape-rooter.service

To restart any service use::

    $ systemctl restart <service_name>

To see service log use::

    $ journalctl -u <service_name>

To install KVM
==============

While you can install and use any hypervisor you like, we recommend using KVM. The script to install everything related to KVM (including KVM itself) can be found here: `kvm-qemu.sh`_.

.. _`kvm-qemu.sh`: https://github.com/doomedraven/Tools/blob/master/Virtualization/kvm-qemu.sh

In order to install KVM itself, execute the following command::

    $ sudo ./kvm-qemu.sh all <username> | tee kvm-qemu.log

`replacing <username> with your actual username.`

Remember to **reboot** after the installation.

If you want to install Virtual Machine Manager (``virt-manager``), execute the following command::

    $ sudo ./kvm-qemu.sh virtmanager <username> | tee kvm-qemu-virt-manager.log

`replacing <username> with your actual username.`

Remember to **reboot** after the installation.