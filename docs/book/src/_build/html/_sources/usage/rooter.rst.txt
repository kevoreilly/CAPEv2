.. _rooter:

=============
CAPE Rooter
=============

The ``CAPE Rooter`` is a new concept, providing ``root`` access for various
commands to CAPE (which itself generally speaking runs as non-root). This
command is currently only available for Ubuntu and Debian-like systems.

In particular, the ``rooter`` helps CAPE out with running network-related
commands to provide **per-analysis routing** options. For more
information on that, please refer to the :ref:`routing` document. CAPE and
the ``rooter`` communicate through a UNIX socket for which the ``rooter``
makes sure that CAPE can reach it.

Its usage is as follows::

    $ python3 rooter.py -h
    usage: rooter.py [-h] [-g GROUP] [--systemctl SYSTEMCTL] [--iptables IPTABLES] [--iptables-save IPTABLES_SAVE] [--iptables-restore IPTABLES_RESTORE] [--ip IP] [-v] [socket]

    positional arguments:
    socket                Unix socket path

    optional arguments:
    -h, --help            show this help message and exit
    -g GROUP, --group GROUP
                            Unix socket group
    --systemctl SYSTEMCTL
                            Systemctl wrapper script for invoking OpenVPN
    --iptables IPTABLES   Path to iptables
    --iptables-save IPTABLES_SAVE
                            Path to iptables-save
    --iptables-restore IPTABLES_RESTORE
                            Path to iptables-restore
    --ip IP               Path to ip
    -v, --verbose         Enable verbose logging

..
    By default, the ``rooter`` will default to ``chown``'ing the ``cape`` user as user and group for the UNIX socket, as recommended when :ref:`../installation/host/installation`.
    If you're running CAPE under a user other than ``cape``, you will have to specify this to the ``rooter`` as follows::

When executing the ``rooter`` utility, it will default to the ``cuckoo`` group.

    .. image:: ../_images/screenshots/rooter_0.png
        :align: center

You must specify the user of the UNIX socket. As recommended in the :ref:`installation`, it should be the **cape** user. You can do so by executing the following command::

    $ sudo python3 utils/rooter.py -g cape

However, if you're running CAPE under a user other than ``cape``, you will have to specify this to the ``rooter`` as follows::

    $ sudo python3 utils/rooter.py -g <user>

The other options are fairly straightforward - you can specify the paths to
specific Linux commands. By default, one shouldn't have to do this though, as
the ``rooter`` takes the default paths for the various utilities as per a
default setup.

Virtualenv
==========

Since the ``rooter`` must be run as ``root`` user, there are
some slight complications when using a ``virtualenv`` to run CAPE. More
specifically, when running ``sudo python3 utils/rooter.py``, the ``$VIRTUAL_ENV``
environment variable will not be passed along, due to which Python will not be
executed from the same ``virtualenv`` as it would have been normally.

To resolve this one simply has to execute the ``cape`` binary from the
``virtualenv`` session directly. E.g., if your ``virtualenv`` is located at
``~/venv``, then running the ``rooter`` command could be done as follows::

    $ sudo ~/venv/bin/cape rooter

.. _cape_rooter_usage:

CAPE Rooter Usage
=================

Using the ``CAPE Rooter`` is pretty easy. If you know how to start
it, you're good to go. Even though CAPE talks with the CAPE
Rooter for each analysis with a routing option other than :ref:`routing_none`,
the CAPE Rooter does not keep any state or attach to any CAPE instance in
particular.

It is therefore that once the CAPE Rooter has been started you may leave it
be - the CAPE Rooter will take care of itself from that point onwards, no
matter how often you restart your CAPE instance.
