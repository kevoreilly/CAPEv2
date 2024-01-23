=============
Configuration
=============

CAPE relies on six main configuration files:

    * :ref:`cuckoo_conf`: for configuring general behavior and analysis options.
    * :ref:`auxiliary_conf`: for enabling and configuring auxiliary modules.
    * :ref:`machinery_conf`: for defining the options for your virtualization software
        (the file has the same name as the machinery module you choose in cuckoo.conf).
    * :ref:`memory_conf`: Volatility configuration.
    * :ref:`processing_conf`: for enabling and configuring processing modules.
    * :ref:`reporting_conf`: for enabling or disabling report formats.
    * :ref:`routing_conf`: for defining the routing of internet connection for the VMs.

To get CAPE working you have to edit :ref:`auxiliary_conf`, :ref:`cuckoo_conf`, and :ref:`machinery_conf` at least.
We suggest you check all configs before starting, to be familiar with the possibilities that you have and what you want to be done.

.. note::
    We recommend to you: create a `custom/conf/` directory and put files in there
    whose names are the same as those in the top-level `conf/` directory. These
    files only need to include settings that will override the defaults.
    In that way you won't have problems with any upcoming changes to default configs.

    To allow for further flexibility, you can also create a `custom/conf/<type>.conf.d/`
    (e.g. `custom/conf/reporting.conf.d/`) directory and place files in there. Any
    file in that directory whose name ends in `.conf` will be read (in lexicographic
    order). The last value read for a value will be the one that is used.

.. warning::
    Any section inside the configs that is marked #community at the top refers to a plugin
    that was developed by our community, but that doesn't mean that we maintain it.
    Those plugins might be outdated or broken due to software/dependency changes.
    If you find anything like this broken, you are more than welcome to fix it and submit a pull request.
    The alternative is to switch off the offending plugin. Opening an issue for any of these is pointless
    as we don't maintain them and cannot support them.

.. _cuckoo_conf:

cuckoo.conf
===========

The first file to edit is *conf/cuckoo.conf*, it contains the generic configuration
options that you might want to verify before launching CAPE.

The file is largely commented and self-explaining, but some of the options you might
want to pay more attention to are:

    * ``machinery`` in ``[cuckoo]``: this defines which Machinery module you want CAPE to use to interact with your analysis machines. The value must be the name of the module without extension.
    * ``ip`` and ``port`` in ``[resultserver]``: defines the local IP address and port that CAPE is going to use to bind the result server to. Make sure this matches the network configuration of your analysis machines, or they won't be able to return the collected results.
    * ``connection`` in ``[database]``: defines how to connect to the internal database. You can use any DBMS supported by `SQLAlchemy`_ using a valid `Database Urls`_ syntax.

.. _`SQLAlchemy`: http://www.sqlalchemy.org/
.. _`Database Urls`: http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls

.. warning:: Check your interface for resultserver IP! Some virtualization software (for example Virtualbox)
    doesn't bring up the virtual networking interfaces until a virtual machine is started.
    CAPE needs to have the interface where you bind the resultserver up before the start, so please
    check your network setup. If you are not sure about how to get the interface up, a good trick is to manually start
    and stop an analysis virtual machine, this will bring virtual networking up.
    If you are using NAT/PAT in your network, you can set up the resultserver IP
    to 0.0.0.0 to listen on all interfaces, then use the specific options `resultserver_ip` and `resultserver_port`
    in *<machinery>.conf* to specify the address and port as every machine sees them. Note that if you set
    resultserver IP to 0.0.0.0 in cuckoo.conf you have to set `resultserver_ip` for all your virtual machines.

.. note:: Default freespace value is 50GB
    It is worth mentioning that the default ``freespace`` value in ``cuckoo.conf`` is 50000 MB aka 50 GB.

Please check the latest version of cuckoo.conf here: `cuckoo.conf`_.

.. _`cuckoo.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/cuckoo.conf

.. _auxiliary_conf:

auxiliary.conf
==============

Auxiliary modules are scripts that run concurrently with malware analysis, this file defines
their options. Please see the latest version here: `auxiliary.conf`_.

.. _`auxiliary.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/auxiliary.conf


.. _machinery_conf:

<machinery>.conf
================

Machinery modules are scripts that define how Cuckoo should interact with
your virtualization software of choice.

Every module should have a dedicated configuration file that defines the
details of the available machines. For example, if you created a *kvm.py*
machinery module, you should specify *kvm* in *conf/cuckoo.conf*
and have a *conf/kvm.conf* file.

CAPE provides some modules by default and for the sake of this guide, we'll
assume you're going to use KVM. Please see the latest version here: `kvm.conf`_.

.. _`kvm.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/kvm.conf

If you are using KVM (kvm.conf), for each VM you want to use for analysis there must be a dedicated section. First you have to create and configure the VM (following the instructions in the dedicated chapter, see :ref:`preparing_the_guest`). The name of the section must be the same as the label of the VM as printed by ``$ virsh list --all``. If no VMs are shown, you can execute the following command sequence: ``$ virsh``, ``$ connect qemu:///system``, ``$ list --all``; or you can check `this link <https://serverfault.com/a/861853>`_ to learn how to change the connection in Virtual Manager.


You can also find examples of other hypervisors like:

* VirtualBox: `virtualbox.conf`_.
* VMWare: `vmware.conf`_.

.. _`virtualbox.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/virtualbox.conf
.. _`vmware.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/vmware.conf

The comments for the options are self-explanatory.

You can use this same configuration structure for any other machinery module, although
existing ones might have some variations or additional configuration options.


.. _memory_conf:

memory.conf
===========

The Volatility tool offers a large set of plugins for memory dump analysis. Some of them are quite slow.
In volatility.conf lets you enable or disable the plugins of your choice.
To use Volatility you have to follow two steps:

 * Enable it in processing.conf
 * Enable memory_dump in cuckoo.conf

In the memory.conf's basic section you can configure the Volatility profile and
the deletion of memory dumps after processing::

    # Basic settings
    [basic]
    # Profile to avoid wasting time identifying it
    guest_profile = WinXPSP2x86
    # Delete memory dump after volatility processing.
    delete_memdump = no

After that every plugin has an own section for configuration::

    # Scans for hidden/injected code and dlls
    # http://code.google.com/p/volatility/wiki/CommandReference#malfind
    [malfind]
    enabled = on
    filter = on

    # Lists hooked api in user mode and kernel space
    # Expect it to be very slow when enabled
    # http://code.google.com/p/volatility/wiki/CommandReference#apihooks
    [apihooks]
    enabled = off
    filter = on

The filter configuration helps you to remove known clean data from the resulting report. It can be configured separately for every plugin.

The filter itself is configured in the [mask] section.
You can enter a list of pids in pid_generic to filter out processes::

    # Masks. Data that should not be logged
    # Just get this information from your plain VM Snapshot (without running malware)
    # This will filter out unwanted information in the logs
    [mask]
    # pid_generic: a list of process ids that already existed on the machine before the malware was started.
    pid_generic = 4, 680, 752, 776, 828, 840, 1000, 1052, 1168, 1364, 1428, 1476, 1808, 452, 580, 652, 248, 1992, 1696, 1260, 1656, 1156

Please see the latest version here: `memory.conf`_.

.. _`memory.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/memory.conf


.. _processing_conf:

processing.conf
===============

This file allows you to enable, disable and configure all processing modules.
These modules are located under `modules/processing/` and define how to digest
the raw data collected during the analysis.

You will find a section for each processing module here: `processing.conf`_.

.. _`processing.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/processing.conf

You might want to configure the `VirusTotal`_ key if you have an account of your own.

.. _`VirusTotal`: http://www.virustotal.com

.. _reporting_conf:

reporting.conf
==============

The *conf/reporting.conf* file contains information on the automated reports generation.
Please see the latest version here: `reporting.conf`_.

.. _`reporting.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/reporting.conf

By setting these options to *on* or *off* you enable or disable the generation
of such reports.

.. _routing_conf:

routing.conf
============

The *conf/routing.conf* file contains information about how the guest VM is connected (or not) to the Internet via the Host, or whether it is isolated. This file is used in conjunction with the ``rooter.py`` utility.

Please see the latest version of routing.conf here: `routing.conf`_.

.. _`routing.conf`: https://github.com/kevoreilly/CAPEv2/blob/master/conf/routing.conf

You can read more about the *routing.conf* file and its options in the :ref:`routing` chapter and more about the ``rooter.py`` utility in the :ref:`rooter` chapter.


Using environment variables in config files
===========================================

Any of the above config files may reference environment variables in their
values by using ``%(ENV:VARIABLE_NAME)s``. For example, instead of putting a
VirusTotal Intelligence API key in :ref:`auxiliary_conf`, you could use the
following::

    [virustotaldl]
    enabled = yes
    dlintelkey = %(ENV:DLINTELKEY)s

assuming the ``DLINTELKEY`` environment variable contains the API key.
