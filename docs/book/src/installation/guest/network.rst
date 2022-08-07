=====================
Network Configuration
=====================

Now it's time to set up the network for your virtual machine.

Windows Settings
================

Before configuring the underlying networking of the virtual machine, you may
want to tweak some settings inside Windows itself.

Two of the most important configurations to make are to **disable** *Windows Firewall* and
*Automatic Updates*. The reason behind this is that these features can affect the behavior
of the malware under normal circumstances and they can pollute the network
analysis performed by CAPE, by dropping connections or including irrelevant
requests.

Windows 10
==========
To do so in Windows 10, open Control Panel and search for ``Windows Defender Firewall``. Disable it completely:

    .. image:: ../../_images/screenshots/guest_win10_disable_firewall.png
        :align: center

    .. image:: ../../_images/screenshots/guest_win10_disable_firewall_1.png
        :align: center

The next step is disabling automatic updates. To do so, open Control Panel and search for ``Administrative Tools``. Open it, then open ``Services``. Look for the ``Windows Update`` entry and double-click on it. Set Startup type to disabled and click stop.

    .. image:: ../../_images/screenshots/guest_win10_disable_updates.png
            :align: center

Windows XP
==========

You can do so from Windows' Control Panel as shown in the picture:

    .. image:: ../../_images/screenshots/windows_security.png
        :align: center

Virtual Networking
==================

Now you need to decide whether you want your virtual machine to be able to access the Internet
or your local network.

To make the virtual machine's networking work properly you'll have to configure your machine's
network so that the Host and the Guest can communicate.

Testing the network access by pinging a guest from the host is good practice, to make sure that the
virtual network was set up correctly.

Only use static IP addresses for your guests, since CAPE doesn't support DHCP (at least, as of this writing).

This stage is very much up to your requirements and the
characteristics of your virtualization software.

    .. warning:: Virtual networking errors!
        Virtual networking is a vital component for CAPE. You must be
        sure that connectivity works between the host and the guests.
        Most of the issues reported by users are related to an incorrect networking setup.
        If you aren't sure about your networking, check your virtualization software
        documentation and test connectivity with ``ping`` and ``telnet``.

The recommended setup is using a Host-Only networking layout with proper
forwarding and filtering configuration done with ``iptables`` on the Host.

We have automated this for you with::

    $ utils/rooter.py

Disable Noisy Network Services
==============================

Windows 7 introduced new network services that create a lot of noise and can hinder PCAP processing.
Disable them by following the instructions below.

Teredo
======

Open a command prompt as Administrator, and run::

    > netsh interface teredo set state disabled


Link Local Multicast Name Resolution (LLMNR)
============================================

Open the Group Policy editor by typing ``gpedit.msc`` into the Start Menu search box, and press Enter.
Then navigate to Computer Configuration> Administrative Templates>
Network> DNS Client, and open Turn off Multicast Name Resolution.

Set the policy to enabled.


Network Connectivity Status Indicator, Error Reporting, etc
===========================================================

Windows has many diagnostic tools such as Network Connectivity Status Indicator and Error Reporting, that reach
out to Microsoft servers over the Internet. Fortunately, these can all be disabled with one Group Policy change.

Open the Group Policy editor by typing ``gpedit.msc`` into the Start Menu search box, and press Enter.
Then navigate to Computer Configuration> Administrative Templates>
System> Internet Communication Management, and open Restrict Internet Communication.

Set the policy to enabled.

``gpedit.msc`` missing
====================

.. warning:: If ``gpedit.msc`` is not present in your system (if you are using Windows 10 Home Edition, for example), you can enable it by executing the following commands from an Administrator command prompt::

    > FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")
    > FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")
If the commands were successful, you should now be able to execute Run (Win+R) -> ``gpedit.msc``.

