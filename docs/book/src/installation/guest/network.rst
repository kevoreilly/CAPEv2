=====================
Network Configuration
=====================

Now it's time to setup the network for your virtual machine.

Windows Settings
================

Before configuring the underlying networking of the virtual machine, you might
want to tweak some settings inside Windows itself.

One of the most important things to do is **disabling** *Windows Firewall* and the
*Automatic Updates*. The reason behind this is that they can affect the behavior
of the malware under normal circumstances and that they can pollute the network
analysis performed by CAPE, by dropping connections or including irrelevant
requests.

You can do so from Windows' Control Panel as shown in the picture:

    .. image:: ../../_images/screenshots/windows_security.png
        :align: center

Virtual Networking
==================

Now you need to decide how to make your virtual machine able to access Internet
or your local network.

In order to make it work properly you'll have to configure your machine's
network so that the Host and the Guest can communicate.
Testing the network access by pinging a guest is a good practice, to make sure the
virtual network was set up correctly.
Use only static IP addresses for your guest, as today CAPE doesn't support DHCP
and using it will break your setup.

This stage is very much up to your own requirements and to the
characteristics of your virtualization software.

    .. warning:: Virtual networking errors!
        Virtual networking is a vital component for CAPE, you must be really
        sure to get connectivity between host and guest.
        Most of the issues reported by users are related to a wrong setup of
        their networking.
        If you aren't sure about that check your virtualization software
        documentation and test connectivity with ping and telnet.

The recommended setup is using a Host-Only networking layout with proper
forwarding and filtering configuration done with ``iptables`` on the Host.

We have automated this for you with:

    $ utils/rooter.py

Disable Noisy Network Services
==============================

Windows 7 introduced new network services that create a lot of noise, and can hinder PCAP processing.
Where's how to disable them:

Teredo
======

Open a command prompt as Administrator, and run:

    netsh interface teredo set state disabled


Link Local Multicast Name Resolution (LLMNR)
============================================

Open the Group Policy editor py typing ``gpedit.msc`` into the Start Menu search box, and press enter.
Then navigate to Computer Configuration> Administrative Templates>
Network> DNS Client, and open Turn off Multicast Name Resolution.

Set the policy to enabled.


Network Connectivity Status Indicator, Error Reporting, etc
===========================================================

Windows has many diagnostic tools such as the Network Connectivity Status Indicator and Error Reporting, that reach
out to Microsoft servers over the internet. Fortunately, these can all be disabled with one Group Policy change.

Open the Group Policy editor py typing ``gpedit.msc`` into the Start Menu search box, and press enter.
Then navigate to Computer Configuration> Administrative Templates>
System> Internet Communication Management, and open Restrict Internet Communication.

Set the policy to enabled.




