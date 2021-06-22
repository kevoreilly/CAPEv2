============================
Per-Analysis Network Routing
============================

The more advanced per-analysis routing, it is naturally
also possible to have one default route - a setup that used to be popular
before, when the more luxurious routing was not yet available.

In our examples we'll be focusing on ``KVM`` as it is our default
machinery choice.


Per-Analysis Network Routing Options
====================================

Following is the list of available routing options.

+-------------------------+--------------------------------------------------+
| Routing Option          | Description                                      |
+=========================+==================================================+
| :ref:`routing_none`     | No routing whatsoever, the only option that does |
|                         | *not* require the Rooter to be run (and   |
|                         | therefore also the **default** routing option).  |
+-------------------------+--------------------------------------------------+
| :ref:`routing_drop`     | Completely drops all non-CAPE traffic,         |
|                         | including traffic within the VMs' subnet.        |
+-------------------------+--------------------------------------------------+
| :ref:`routing_internet` | Full internet access as provided by the given    |
|                         | network interface (similar to the                |
|                         | :ref:`simple_global_routing` setup).             |
+-------------------------+--------------------------------------------------+
| :ref:`routing_inetsim`  | Routes all traffic to an InetSim instance -      |
|                         | which provides fake services - running on the    |
|                         | host machine.                                    |
+-------------------------+--------------------------------------------------+
| :ref:`routing_tor`      | Routes all traffic through Tor.                  |
+-------------------------+--------------------------------------------------+
| :ref:`routing_vpn`      | Routes all traffic through one of perhaps        |
|                         | multiple pre-defined VPN endpoints.              |
+-------------------------+--------------------------------------------------+
| :ref:`routing_socks`    | Routes all traffic through one of perhaps        |
|                         | multiple pre-defined VPN endpoints.              |
+-------------------------+--------------------------------------------------+

Using Per-Analysis Network Routing
==================================

Having knowledge about the available network routing options it is time to
actually use it in practice. Assuming CAPE has been configured properly
taking advantage of its features is really as simple as **starting the CAPE
Rooter and choosing a network routing option for your analysis**.

Documentation on starting the ``Rooter`` may be found in the
:ref:`cape_rooter_usage` document.

Both global routing and per-analysis routing require ip forwarding to be enabled:

    $ echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
    $ sudo sysctl -w net.ipv4.ip_forward=1

.. _routing_iproute2:

Configuring iproute2
====================

For Linux kernel TCP/IP source routing reasons it is required to register each
of the network interfaces that we use with ``iproute2``. This is trivial, but
necessary.

As an example we'll be configuring :ref:`routing_internet` (aka the
``dirty line``) for which we'll be using the ``eth0`` network interface -
reverting back to Ubuntu 14.04 and older terminology here for a second (Ubuntu
16.04 uses network interface names based on the hardware manufacturer, as you
will likely have seen happen on BSD-based systems since forever).

To configure ``iproute2`` with ``eth0`` we're going to open the
``/etc/iproute2/rt_tables`` file which will look roughly as follows::

    #
    # reserved values
    #
    255     local
    254     main
    253     default
    0       unspec
    #
    # local
    #

Now roll a random number that is not yet present in this file with your dice
of choice and use it to craft a new line at the end of the file. As an
example, registering ``eth0`` with ``iproute2`` could look as follows::

    #
    # reserved values
    #
    255     local
    254     main
    253     default
    0       unspec
    #
    # local
    #

    400     eth0

And that's really all there is to it. You will have to do this for each
network interface you intend to use for network routing.

.. _routing_none:

None Routing
^^^^^^^^^^^^

The default routing mechanism in the sense that CAPE allows the analysis to
route as defined by a third party. As in, it literally doesn't do anything.
One may use the ``none routing`` in conjunction with the
:ref:`simple_global_routing`.

.. _routing_drop:

Drop Routing
^^^^^^^^^^^^

The ``drop routing`` option is somewhat like a default :ref:`routing_none`
setup (as in, in a machine where no global ``iptables`` rules have been
created providing full internet access to VMs or so), except that it is much
more aggressive in actively locking down the internet access provided to the
VM.

With ``drop routing`` the only traffic possible is internal CAPE traffic and
hence any ``DNS`` requests or outgoing ``TCP/IP`` connections are blocked.

.. _routing_internet:

Internet Routing
^^^^^^^^^^^^^^^^

By using the ``internet routing`` one may provide full internet access to VMs
through one of the connected network interfaces. We also refer to this option
as the ``dirty line`` due to its nature of allowing all potentially malicious
samples to connect to the internet through the same uplink.

.. note:: It is required to register the dirty line network interface with
    iproute2 as described in the :ref:`routing_iproute2` section.

.. _routing_inetsim:

InetSim Routing
^^^^^^^^^^^^^^^

For those that have not heard of `InetSim`_, it's a project that provides
fake services for malware to talk to. In order to use ``InetSim routing`` one
will have to setup InetSim on the host machine (or in a separate VM) and
configure CAPE so that it knows where to find the InetSim server.

The configuration for InetSim is self-explanatory and can be found as part
of the ``$CWD/conf/routing.conf`` configuration file::

    [inetsim]
    enabled = yes
    server = 192.168.122.1

In order to quickly get started with InetSim it is possible to download
the latest version of the `REMnux`_ distribution which features - among many
other tools - the latest version of InetSim. Naturally this VM will
require its own static IP address which should then be configured in the
``routing.conf`` configuration file.

.. _InetSim: http://www.inetsim.org/
.. _REMnux: https://remnux.org/

.. _routing_tor:

We ``Suggest to run it in virtual machine`` to avoid any possible leaks

Tor Routing
^^^^^^^^^^^

.. note:: Although we **highly discourage** the use of Tor for malware analysis
    - the maintainers of ``Tor exit nodes`` already have a hard enough time
    keeping up their servers - it is in fact a well-supported feature.

First of all Tor will have to be installed. Please find instructions on
installing the `latest stable version of Tor here`_.

We'll then have to modify the ``Tor`` configuration file (not talking about
CAPE's configuration for Tor yet!) In order to do so, we will have to
provide Tor with the listening address and port for TCP/IP connections and UDP
requests. For a default ``KVM`` setup, where the host machine has IP
address ``192.168.122.1``, the following lines will have to be configured in
the ``/etc/tor/torrc`` file::

    TransPort 192.168.122.1:9040
    DNSPort 192.168.122.1:5353

Don't forget to restart Tor (``/etc/init.d/tor restart``). That leaves us with
the Tor configuration for Cuckoo, which may be found in the
``$CWD/conf/routing.conf`` file. The configuration is pretty self-explanatory
so we'll leave filling it out as an exercise to the reader (in fact, toggling
the ``enabled`` field goes a long way)::

    [tor]
    enabled = yes
    dnsport = 5353
    proxyport = 9040

Note that the port numbers in the ``/etc/tor/torrc`` and
``$CWD/conf/routing.conf`` files must match in order for the two to interact
correctly.

.. _`latest stable version of Tor here`: https://www.torproject.org/docs/debian.html.en

.. _routing_vpn:

VPN Routing
^^^^^^^^^^^

It is possible to route analyses through a number of VPNs.
By defining a couple of VPNs, perhaps ending up in different countries, it may
be possible to see if potentially malicious samples behave differently
depending on the country of origin of its IP address.

The configuration for a VPN is much like the configuration of a VM. For each
VPN you will need one section in the ``$CWD/conf/routing.conf`` configuration
file detailing the relevant information for the VPN. In the configuration the
VPN will also have to be *registered* in the list of available VPNs (exactly
the same as you'd do for registering more VMs).

Configuration for a single VPN looks roughly as follows::

    [vpn]
    # Are VPNs enabled?
    enabled = yes

    # Comma-separated list of the available VPNs.
    vpns = vpn0

    [vpn0]
    # Name of this VPN. The name is represented by the filepath to the
    # configuration file, e.g., CAPE would represent /etc/openvpn/cuckoo.conf
    # Note that you can't assign the names "none" and "internet" as those would
    # conflict with the routing section in cuckoo.conf.
    name = vpn0

    # The description of this VPN which will be displayed in the web interface.
    # Can be used to for example describe the country where this VPN ends up.
    description = Spain, Europe

    # The tun device hardcoded for this VPN. Each VPN *must* be configured to use
    # a hardcoded/persistent tun device by explicitly adding the line "dev tunX"
    # to its configuration (e.g., /etc/openvpn/vpn1.conf) where X in tunX is a
    # unique number between 0 and your lucky number of choice.
    interface = tun0

    # Routing table name/id for this VPN. If table name is used it *must* be
    # added to /etc/iproute2/rt_tables as "<id> <name>" line (e.g., "201 tun0").
    # ID and name must be unique across the system (refer /etc/iproute2/rt_tables
    # for existing names and IDs).
    rt_table = tun0

.. note:: It is required to register each VPN network interface with iproute2
    as described in the :ref:`routing_iproute2` section.

* `Helper script, read code to understand it`_
* `Example of wireguard integration`_
.. _`Helper script, read code to understand it`: https://github.com/kevoreilly/CAPEv2/blob/master/utils/vpn2cape.py
.. _`Example of wireguard integration`: https://musings.konundrum.org/2020/12/12/wireguard-and-cape.html

VPN persistance & autorestart `source`_::

    1. Run the command:
        # sudo nano /etc/default/openvpn`
        and uncomment, or remove, the “#” in front of AUTOSTART="all"
        then press ‘Ctrl X’ to save the changes and exit the text editor.

    2. Move the .ovpn file with the desired server location to the ‘/etc/openvpn’ folder:
        # sudo cp /location/whereYouDownloadedConfigfilesTo/Germany.ovpn /etc/openvpn/

    3. In the ‘/etc/openvpn’ folder, create a text file called login.creds:
        # sudo nano /etc/openvpn/login.creds
        and enter your IVPN Account ID (starts with ‘ivpn’) on the first line and any non-blank text on the 2nd line, then press ‘Ctrl X’ to save the changes and exit the text editor.

    4. Change the permissions on the pass file to protect the credentials:
        # sudo chmod 400 /etc/openvpn/login.creds

    5. Rename the .ovpn file to ‘client.conf’:
        # sudo cp /etc/openvpn/Germany.ovpn /etc/openvpn/client.conf

    6. Reload the daemons:
    # sudo systemctl daemon-reload

    7. Start the OpenVPN service:
        # sudo systemctl start openvpn

    8. Test if it is working by checking the external IP:
        # curl ifconfig.co

    9. If curl is not installed:
        # sudo apt install curl

.. _`source`: https://www.ivpn.net/knowledgebase/linux/linux-autostart-openvpn-in-systemd-ubuntu/

.. _routing_socks:

SOCKS Routing
^^^^^^^^^^^^^
You also can use socks proxy servers to route your traffic.
To manage your socks server you can use Socks5man software.
Bulding them by yourself, using your favorite software, bying, etc
The configuration is pretty simple, and looks like VPN, but you don't need to configure nothing else

Example::

    [socks5]
    # By default we disable socks5 support as it requires running utils/rooter.py as
    # root next to cuckoo.py (which should run as regular user).
    enabled = no

    # Comma-separated list of the available proxies.
    proxies = socks_CC

    [socks_CC]
    name = CC_socks
    description = CC_socks
    proxyport = 5000
    dnsport = 10000
