===============
Troubleshooting
===============

No Internet connection in the guest
===================================
There are reasons galore why your guest VM has no Internet connection when an analysis is fired up. Before digging into this problem, please make sure you followed the steps at :ref:`Network Configuration` to set up both the virtual machine and its connections. Furthermore, you should read the :ref:`routing` chapter in order to know and understand the different routing modes as well as the :ref:`rooter` chapter to understand what the ``Rooter`` is. 

Some considerations:

1. ``dirtyline`` should be the **interface that provides your host internet connection** like **eno1**, not a virtual interface like *virbr1*. This must be configured in the ``routing.conf`` configuration file.
2. Check ``agent.py`` is running with elevated privileges within the guest VM. 
3. Make sure you specify the correct **STATIC** IP in ``kvm.conf``.
4. Make sure you specified the correct interface in ``auxiliary.conf``.

Also, bear in mind there are already created (and some of them solved) issues about this particular problem. For example:

* https://github.com/kevoreilly/CAPEv2/issues/1234
* https://github.com/kevoreilly/CAPEv2/issues/1245
* https://github.com/kevoreilly/CAPEv2/issues/371
* https://github.com/kevoreilly/CAPEv2/issues/367
* https://github.com/kevoreilly/CAPEv2/issues/136

PCAP Generation
===============

If you are facing problems related to either tcpdump or the PCAP generation, take a look at `this issue (#1234) <https://github.com/kevoreilly/CAPEv2/issues/1234>`_.

.. note::

    Make sure the ``pcap`` group exists in your system and that the user you use to launch CAPE (presumably the `cape` user) belongs to it as well as the ``tcpdump`` binary.

Make sure the correct path is specified in ``auxiliary.conf`` for ``tcpdump``. Check the path of your local installation of tcpdump with::

    $ whereis tcpdump

Check permissions of ``tcpdump`` binary. ``cape`` user must be able to run it. Also check whether you specified the correct interface in ``auxiliary.conf``.

If you are still facing problems and the PCAP is not generating, verify the ``tcpdump`` binary belongs to the ``pcap`` group and it has the neede capabilities::

    $ sudo chgrp pcap /usr/bin/tcpdump
    $ sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

Other issues about this problem:

* https://github.com/kevoreilly/CAPEv2/issues/1193
