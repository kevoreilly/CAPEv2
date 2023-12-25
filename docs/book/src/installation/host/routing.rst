.. _routing:

============================
Per-Analysis Network Routing
============================

With the more advanced per-analysis routing, it is naturally
also possible to have one default route - a setup that used to be popular
before, when the more luxurious routing was not yet available.

In our examples, we'll be focusing on ``KVM`` as it is our default
machinery choice.


.. warning::
    In case if you see proxy IP:PORT in networking for example as tor `9040` port.
    It happens due that you have installed `docker` on your host and it breaks some networking filters.

To fix proxy IP:PORT problem, you need to run following script.
Save it to file, give execution permission with sudo a+x iptables_fix.sh and run it with proper arguments::

    !/bin/bash
    # Fix when docker breaks your iptables
    if [ $# -eq 0 ] || [ $# -lt 2 ]; then
        echo "$0 <network range> <vir_iface> <real_iface>"
        echo "    example: $0 192.168.1.0 virbr0 eno0"
        exit 1
    fi

    echo "[+] Setting iptables"
    iptables -t nat -A POSTROUTING -o "$2" -j MASQUERADE
    iptables -A FORWARD -i "$2" -o "$2" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$2" -o "$2" -j ACCEPT
    iptables -I FORWARD -m physdev --physdev-is-bridged -j ACCEPT
    iptables -I FORWARD -o "$2" -d  "$1"/24 -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$1"/24 -j MASQUERADE
    iptables -A FORWARD -o "$2" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$2" -o "$3" -j ACCEPT
    iptables -A FORWARD -i "$2" -o lo -j ACCEPT

    echo "[+] Setting network options"
    # https://forums.fedoraforum.org/showthread.php?312824-Bridge-broken-after-docker-install&s=ffc1c60cccc19e46c01b9a8e0fcd0c35&p=1804899#post1804899
    {
        echo "net.bridge.bridge-nf-call-ip6tables=0";
        echo "net.bridge.bridge-nf-call-iptables=0";
        echo "net.bridge.bridge-nf-call-arptables=0";
        echo "net.ipv4.conf.all.forwarding=1";
        echo "net.ipv4.ip_forward=1";
    } >> /etc/sysctl.conf
    sysctl -p
    echo "iptables -A FORWARD -i $2 -o $2 -j ACCEPT" >> /etc/network/if-pre-up.d/kvm_bridge_iptables

    virsh nwfilter-list

To make it permanent you can use `iptables-save`.


Per-Analysis Network Routing Options
====================================

Following is the list of available routing options.

+-------------------------+--------------------------------------------------+
| Routing Option          | Description                                      |
+=========================+==================================================+
| :ref:`routing_none`     | No routing whatsoever, the only option that does |
|                         | *not* require the Rooter to be run (and          |
|                         | therefore also the **default** routing option).  |
+-------------------------+--------------------------------------------------+
| :ref:`routing_drop`     | Completely drops all non-CAPE traffic,           |
|                         | including traffic within the VMs' subnet.        |
+-------------------------+--------------------------------------------------+
| :ref:`routing_internet` | Full internet access as provided by the given    |
|                         | network interface                                |
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

Now that you know the available network routing options, it is time to
use them in practice. Assuming CAPE has been configured properly
taking advantage of its features is as simple as **starting the CAPE
Rooter and choosing a network routing option for your analysis**.

Documentation on starting the ``Rooter`` may be found in the
:ref:`cape_rooter_usage` document.

Both global routing and per-analysis routing require ip forwarding to be enabled::

    $ echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
    $ sudo sysctl -w net.ipv4.ip_forward=1

.. warning::
    Please be aware by default these changes do not persist and will be reset after a system restart.

.. _routing_netplan:

Configuring netplan
===================

In modern releases of Ubuntu, all network configuration is handled by
``netplan``, including routing tables.

If you are using Ubuntu Server, disable ``cloud-init``, which is used by
default.

Do this by writing a file at
``/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg``, with the
content ``network: {config: disabled}``, then delete
``/etc/netplan/50-cloud-init.yaml``.

If you are using a desktop version of Ubuntu instead,
you will need to disable ``NetworkManager`` and enable ``networkd``.

.. code:: text

   sudo systemctl stop NetworkManager
   sudo systemctl disable NetworkManager
   sudo systemctl mask NetworkManager

   sudo systemctl unmask systemd-networkd
   sudo systemctl enable systemd-networkd
   sudo systemctl start systemd-networkd

Next, create your own ``netplan`` configuration file manually at
``/etc/netplan/99-manual.yaml``

The example ``netplan`` configuration below has a 5G hotspot interface named
``enx00a0c6000000`` for :ref:`routing_internet` (aka the
``dirty line``) and a management interface named ``enp8s0`` for hosting the
CAPE web UI, SSH and other administrative services. In this configuration the
dirty line is used as the default gateway for all internet traffic on the host.
This helps prevent network leaks, firewall IDS/IPS issues, and keeps
administrative traffic separate, where it could be placed in its own subnet
for additional security.

You will need to replace the interface names and IP addresses to reflect your
own system.

Each interface configuration needs a ``routes`` section that describes the
routes that can be accessed via that interface. In order for the configuration
to work with CAPE's per-analysis routing, each ``routes`` section must have an
arbitrary but unique ``table`` integer value.

.. code:: yaml

   network:
       version: 2
       renderer: networkd
       ethernets:
           lo:
               addresses: [ "127.0.0.1/8", "::1/128", "7.7.7.7/32" ]
           enx00a0c6000000:
               dhcp4: no
               addresses: [ "192.168.1.2/24" ]
               nameservers:
                   addresses: [ "192.168.1.1" ]
               routes:
                   - to: default
                     via: 192.168.1.1
                   - to: 192.168.1.0/24
                     via: 192.168.1.1
                     table: 101
               routing-policy:
                - from: 192.168.1.0/24
                  table: 101
           enp8s0:
               dhcp4: no
               addresses: [ "10.23.6.66/24" ]
               routes:
                   - to: 10.23.6.0/24
                     via: 10.23.6.1
                     table: 102
               routing-policy:
                   - from: 10.23.6.0/24
                     table: 102

Run ``sudo netplan apply`` to apply the new ``netplan`` configuration. You can verify the new routing rules and tables have been created with:

* ``ip r``. To show 'main' table.
* ``ip r show table X``. To show 'X' table, where X is either the number or the name you specified in the netplan file.
* ``ip r show table all``. To show all routing rules form all tables.

.. note::
    There are some considerations you should take into account when configuring and setting netplan and others components necessary so as to provide the Hosts with Internet connection:

        * IP forwarding **MUST** be enabled.
        * The routing table **NUMBER** specified in the netplan config file should be the **SAME** as the one specified in ``/etc/iproute2/rt_tables``.
        * The routing table **NAME** specified in ``/etc/iproute2/rt_tables`` (next to its number) should be the **SAME** as the one specified specified in ``routing.conf`` (with the ``rt_table`` field).

.. _routing_firewall:

Protecting host ports
=====================

By default, most Linux network services listen on all network interface
interfaces/addresses, leaving the services running on the host machine
exposed to potential attacks from the analysis VMs.

To mitigate this issue, use the ``ufw`` firewall included with Ubuntu.
It will not break CAPE’s per-analysis network routing.

Allow access to administrative services using the interface that is
being used for management of the sandbox. Network interface details can
be found by using the ``ip addr`` command.

In this example the management interface name is ``enp8s0``, with an IP
address of ``10.23.6.66``. Replace these values with the proper values
for your server.

.. code:: bash

   # HTTP
   sudo ufw allow in on enp8s0 to 10.23.6.66 port 80 proto tcp

   # HTTPS
   sudo ufw allow in on enp8s0 to 10.23.6.66 port 443 proto tcp

   # SSH
   sudo ufw allow in on enp8s0 to 10.23.6.66 port 22 proto tcp

   # SMB (smbd is enabled by default on desktop versions of Ubuntu)
   sudo ufw allow in on enp8s0 to 10.23.6.66 port 22 proto tcp

   # RDP (if xrdp is used on the server)
   sudo ufw allow in on enp8s0 to 10.23.6.66 port 445 proto tcp

Allow analysis VMs to access the CAPE result server, which used TCP port
``2042`` by default.

In this example the host interface name is ``virbr1`` with an IP address
of ``192.168.42.1``. Replace these values with the proper values for
your server.

.. code:: bash

   sudo ufw allow in on virbr1 to 192.168.42.1 port 2042 proto tcp

Enable the firewall after all of the rules have ben configured.

.. code:: bash

   sudo ufw enable


.. _routing_none:

None Routing
^^^^^^^^^^^^

The default routing mechanism in the sense that CAPE allows the analysis to
route as defined by a third party. As in, it doesn't do anything.
One may use the ``none routing``

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
    iproute2 as described in the :ref:`routing_netplan` section.

.. _routing_inetsim:

InetSim Routing
^^^^^^^^^^^^^^^

For those that have not heard of `InetSim`_, it's a project that provides
fake services for malware to talk to. To use ``InetSim routing`` one
will have to set up InetSim on the host machine (or in a separate VM) and
configure CAPE so that it knows where to find the InetSim server.

The configuration for InetSim is self-explanatory and can be found as part
of the ``$CWD/conf/routing.conf`` configuration file::

    [inetsim]
    enabled = yes
    server = 192.168.122.1

To quickly get started with InetSim it is possible to download
the latest version of the `REMnux`_ distribution which features - among many
other tools - the latest version of InetSim. Naturally, this VM will
require a static IP address which should then be configured in the
``routing.conf`` configuration file.

.. _InetSim: http://www.inetsim.org/
.. _REMnux: https://remnux.org/

We ``suggest running it on a virtual machine`` to avoid any possible leaks

.. _routing_tor:

Tor Routing
^^^^^^^^^^^

.. note:: Although we **highly discourage** the use of Tor for malware analysis
    - the maintainers of ``Tor exit nodes`` already have a hard enough time
    keeping up their servers - it is a well-supported feature.

First of all, Tor will have to be installed. Please find instructions on
installing the `latest stable version of Tor here`_.

We'll then have to modify the ``Tor`` configuration file (not talking about
CAPE's configuration for Tor yet!) To do so, we will have to
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
``$CWD/conf/routing.conf`` files must match for the two to interact
correctly.

.. _`latest stable version of Tor here`: https://www.torproject.org/docs/debian.html.en

.. _routing_vpn:

VPN Routing
^^^^^^^^^^^

It is possible to route analyses through multiple VPNs.
By defining a couple of VPNs, perhaps ending up in different countries, it may
be possible to see if potentially malicious samples behave differently
depending on the country of origin of their IP address.

The configuration for a VPN is much like the configuration of a VM. For each
VPN you will need one section in the ``$CWD/conf/routing.conf`` configuration
file detailing the relevant information for the VPN. In the configuration, the
VPN will also have to be *registered* in the list of available VPNs
(the same as you'd do for registering more VMs).

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

.. note:: It is required to register each VPN network interface with netplan
    as described in the :ref:`routing_netplan` section.

Quick and dirty example of iproute2 configuration for VPN::

    Example:
        /etc/iproute2/rt_tables
            5 host1
            6 host2
            7 host3

        conf/routing.conf
            [vpn5]
            name = X.ovpn
            description = X
            interface = tunX
            rt_table = host1

Bear in mind that you will need to adjust some values inside of `VPN route script`_. Read it!

* `Helper script vpt2cape.py, read code to understand it`_

.. _`Helper script vpt2cape.py, read code to understand it`: https://github.com/kevoreilly/CAPEv2/blob/master/utils/vpn2cape.py
.. _`VPN route script`: https://github.com/kevoreilly/CAPEv2/blob/master/utils/route.py

VPN persistence & auto-restart `source`_::

    1. Run the command:
        # sudo nano /etc/default/openvpn`
        and uncomment, or remove, the “#” in front of AUTOSTART="all"
        then press ‘Ctrl X’ to save the changes and exit the text editor.

    2. Move the .ovpn file with the desired server location to the ‘/etc/openvpn’ folder:
        # sudo cp /location/whereYouDownloadedConfigFilesTo/Germany.ovpn /etc/openvpn/

    3. In the ‘/etc/openvpn’ folder, create a text file called login.creds:
        # sudo nano /etc/openvpn/login.creds
        and enter your IVPN Account ID (starts with ‘ivpn’) on the first line and any non-blank text on the 2nd line, then press ‘Ctrl X’ to save the changes and exit the text editor.

    4. Change the permissions on the pass file to protect the credentials:
        # sudo chmod 400 /etc/openvpn/login.creds

    5. Rename the .ovpn file to ‘client.conf’:
        # sudo cp /etc/openvpn/Germany.ovpn /etc/openvpn/client.conf

    6. Reload the daemons:
    # sudo systemctl daemon-reload

    1. Start the OpenVPN service:
        # sudo systemctl start openvpn

    2. Test if it is working by checking the external IP:
        # curl ifconfig.co

    3. If curl is not installed:
        # sudo apt install curl

.. _`source`: https://www.ivpn.net/knowledgebase/linux/linux-autostart-openvpn-in-systemd-ubuntu/

.. _routing_socks:

Wireguard VPN
^^^^^^^^^^^^^

Setup Wireguard
===============

* `Original blog post on how to setup WireGuard with CAPE`_

Install wireguard::

    sudo apt install wireguard

Download Wireguard configurations from your VPN provider and copy them into ``/etc/wireguard/wgX.conf``. E.g.::

    /etc/wireguard/wg1.conf
    /etc/wireguard/wg2.conf
    /etc/wireguard/wg3.conf

Each configuration is for a different exit destination.

An example config for wg1.conf::

    # VPN-exit-CC
    [Interface]
    PrivateKey = <REMOVED>
    Address = xxx.xxx.xxx.xxx/32
    Table = 420

    # Following 2 lines added in attempt to allow local traffic
    PreUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o %i -j MASQUERADE
    PreDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o %i -j MASQUERADE

    [Peer]
    PublicKey = <REMOVED>
    AllowedIPs = 0.0.0.0/0
    Endpoint = xxx.xxx.xxx.xxx:51820

The only changes I made to the original file from my VPN provider was adding ``Table = 420`` and the ``PreUp`` and ``PreDown`` lines to configure iptables.

Then start the VPN: ``wg-quick up wg1``. If all goes well you can run wg and see that the tunnel is active. If you want to test it’s working I suggest::

    curl https://ifconfig.me/
    curl --interface wg1 https://ifconfig.me/

Example snippet from ``/opt/CAPEv2/conf/routing.conf`` configuration::

    [vpn0]
    name = vpn0
    description = vpn_CC_wg1
    interface = wg1
    rt_table = wg1

.. note:: It is required to register each VPN network interface with netplan
    as described in the :ref:`routing_netplan` section. Check quick and dirty note in original VPN section.

.. _`Original blog post on how to setup WireGuard with CAPE`: https://musings.konundrum.org/2020/12/12/wireguard-and-cape.html

SOCKS Routing
^^^^^^^^^^^^^
You also can use socks proxy servers to route your traffic.
To manage your socks server you can use Socks5man software.
Building them by yourself, using your favorite software, buying, etc
The configuration is pretty simple and looks like VPN, but you don't need to configure anything else

Requires to install dependency: ``poetry run pip install git+https://github.com/CAPESandbox/socks5man``

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

===============
Troubleshooting
===============

Configuring the Internet connection in the Hosts (VMs) can become a tedious task given the elements involved in the correct functioning. Here you can find several ways of debugging the connections from and to the Hosts besides ``cuckoo.py -d``.

Manually testing Internet connection
====================================
You can manually test the Internet connection from inside the VMs without the need of performing any analysis. To do so, you have to use the . This utility allows you to enable or disable specific **routes** and debug them. It is a "Standalone script to debug VM problems that allows to enable routing on VM".

First, **stop** the ``cape-rooter`` service with::

    $ sudo systemctl stop cape-rooter.service

Assuming you already have any VM running, to test the internet connection using ``router_manager.py`` you have to execute the following commands::

    $ sudo python3 router_manager.py -r internet -e --vm-name win1 --verbose
    $ sudo python3 router_manager.py -r internet -d --vm-name win1 --verbose

The ``-e`` flag is used to enable a route and ``-d`` is used to disable it. You can read more about all the options the utility has by running:: 

    $ sudo python3 router_manager.py -h

.. note:: The `--vm-name` parameters expects any ID from the ones in <machinery>.conf, not the label you named each VM with. To see the available options you can execute ``$ sudo python3 router_manager.py --show-vm-names``.

Whenever you use the `router_manager.py <https://github.com/kevoreilly/CAPEv2/blob/master/utils/router_manager.py>`_ utility to either enable or disable any given route, there are changes made to ``iptables`` are you should be able to see them take place.

For instance, this is how it looks **BEFORE** enabling any route::


    $ ip rule
    0:  from all lookup local
    32766:  from all lookup main
    32767:  from all lookup default


And this is how it looks **AFTER** executing the following commands::

    $ sudo python3 router_manager.py -r internet -e --vm-name win1 --verbose
    internet eno1 eno1 {'label': 'win10', 'platform': 'windows', 'ip': 'X.X.X.133', 'arch': 'x64'} None None
    $ sudo python3 router_manager.py -r internet -e --vm-name win2 --verbose
    internet eno1 eno1 {'label': 'win10-clone', 'platform': 'windows', 'ip': 'X.X.X.134', 'arch': 'x64'} None None

    $ ip rule
    0:  from all lookup local
    32764:  from X.X.X.134 lookup eno1
    32765:  from X.X.X.133 lookup eno1
    32766:  from all lookup main
    32767:  from all lookup default

Then again, if everything is configured as expected, when executing the utility with the ``-d`` option the IP rules should disappear, reverting them to their original state.

If your routing configuration is correct, you should now be able to successfully ``ping 8.8.8.8``. If you disable the route you shouldn't be able to ping anything on the Internet.

.. note::
    Sometimes ip rules may remain undeleted for several reasons. You can manually delete them with ``$ sudo ip rule delete from $IP``, where $IP is the IP the rule refers to.

Debugging ``iptables`` rules
=============================

Every single time the :ref:`rooter` brings up or down any route (assuming it works as expected) or you do so by using the `router_manager.py <https://github.com/kevoreilly/CAPEv2/blob/master/utils/router_manager.py>`_ utility, your iptables set of rules is modified in one way or another.

To inspect the changes being made and verify them, you can use the ``watch`` utility preinstalled in the vast majority of \*nix systems. For example, to view rules created by CAPE-rooter or the utility you can run the following command::

    $ sudo watch -n 1 iptables -L -n -v

You can also leverage ``watch`` to inspect the connections being made from the Guest to the Host or viceversa::

    $ sudo watch -n 1 'netstat -peanut | grep $IP'

where $IP is the IP of your Guest.



