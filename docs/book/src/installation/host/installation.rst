.. _installation:

=================
Installing CAPE
=================

Proceed with download and installation. Read :doc:`../../introduction/what` to
learn where you can obtain a copy of the sandbox.

Automated installation, read the full page before you start
===========================================================

We have automated all work for you, but bear in mind, that 3rd party dependencies change frequently and can break the installation,
so please check the installation log and try to provide the fix / correct issue to the developers.

To install KVM
==============

While you can install and use any hypervisor you like, we recommend using KVM. The script to install everything related to KVM (including KVM itself) can be found here: `kvm-qemu.sh`_.

.. note:: We recommend using the script to install everything related with KVM-Qemu since the script performs a stealthier configuration and achieves better performance than the installation from APT.

.. _`kvm-qemu.sh`: https://github.com/doomedraven/Tools/blob/master/Virtualization/kvm-qemu.sh

**BEFORE** executing the script, you should replace the **<WOOT>** occurrences withing the script itself with real hardware patterns. You can use ``acpidump`` in Linux and ``acpiextract`` in Windows to obtain such patterns, as stated `in the script itself`_.

    .. warning:: If you are installing or using CAPE in a laboratory environment you can replace **<WOOT>** with any random 4 chars you like. However, if you are planning to use CAPE in real production environments and you want to hinder the sandbox/VM detection, you should use *REAL* hardware 4 chars. To find out which chars correspond to each piece of HW, you should use ACPIDUMP/ACPIEXTRACT and Google.

.. _`in the script itself`: https://github.com/doomedraven/Tools/blob/master/Virtualization/kvm-qemu.sh#L37

In order to install KVM itself, execute the following command::

    $ sudo ./kvm-qemu.sh all <username> | tee kvm-qemu.log

`replacing <username> with your actual username.`

Remember to **reboot** after the installation.

If you want to install Virtual Machine Manager (``virt-manager``), execute the following command::

    $ sudo ./kvm-qemu.sh virtmanager <username> | tee kvm-qemu-virt-manager.log

`replacing <username> with your actual username.`

Remember to **reboot** after the installation.


To install CAPE
================

The script to install CAPE can be found here: `cape2.sh`_.

.. _`cape2.sh`: https://github.com/kevoreilly/CAPEv2/blob/master/installer/cape2.sh

    .. note:: CAPE is being maintained and updated in a `rolling <https://en.wikipedia.org/wiki/Rolling_release>`_ fashion. That is, there are no versions or releases. It is your responsibility to regularly ``pull`` the repo and stay up to date.

You need to give execution permission to script `chmod a+x cape2.sh`. Please keep in mind that all our scripts use the ``-h`` flag to print the help and usage message. However, it is recommended to read the scripts themselves to **understand** what they do.

Please become familiar with available options using::

    $ ./cape2.sh -h

To install CAPE with all the optimizations, use one of the following commands::

    $ sudo ./cape2.sh base cape | tee cape.log
    $ sudo ./cape2.sh all cape | tee cape.log

The main difference between **base** and **all** is that **all** installs virt-manager, which is GUI for libvirt. This is useless if the installation is performed on a server, for example.

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

To install dependencies
=======================

You can install CAPE's dependencies with the traditional. However, we recommend using poetry. As all services are configured to use poetry and better deal with dependencies conflict. See next step for poetry::
    $ pip3 install -r requirements.txt

To install dependencies with poetry, execute the following command (from the main working directory of CAPE, usually ``/opt/CAPEv2/``)::

    $ sudo poetry install

Once the installation is done, you can confirm a virtual environment has been created with::

    $ poetry env list

The output should be similar to::

    $ poetry env list
    capev2-t2x27zRb-py3.10 (Activated)

From now on, you will have to execute CAPE within the virtual env of Poetry. To do so you need just ``poetry run <command>``. For example::

    $ sudo -u cape poetry run python3 cuckoo.py

If you need further assistance with Poetry, there are hundreds of cheatsheets on the Internet

============================
**ATTENTION!** ``cape`` user
============================

Only the installation scripts and some utilities like ``rooter.py`` must be executed with ``sudo``, the rest of configuration scripts and programs **MUST** be executed under the ``cape`` user, which is created in the system after executing ``cape2.sh``.

By default, the cape user has no login. In order to substitute it and use the cmd on its behalf, you can execute the following command::

    $ sudo su - cape -c /bin/bash
