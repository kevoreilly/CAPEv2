============
Requirements
============

Before proceeding on configuring Cuckoo, you'll need to install some required
software and libraries.

Installing Python libraries
===========================

Cuckoo host components are completely written in Python, therefore make sure to
have an appropriate version installed. For the current release **Python 2.7** is preferred.

Install Python on Ubuntu::

    $ sudo apt-get install python

If you want to use the Django-based web interface, you'll have to install MongoDB or ElasticSearch.

MongoDB::

    $ sudo apt-get install mongodb

ElasticSearch::

    $ add-apt-repository ppa:webupd8team/java
    $ wget -qO - https://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
    $ add-apt-repository "deb http://packages.elasticsearch.org/elasticsearch/1.4/debian stable main"
    $ apt-get update
    $ apt-get install oracle-java8-installer elasticsearch
    $ apt-get install elasticsearch
    $ update-rc.d elasticsearch defaults 95 10
    $ /etc/init.d/elasticsearch start

In order to properly function, Cuckoo requires SQLAlchemy and Python BSON to be installed.

Install with ``apt-get``::

    $ sudo apt-get install python-sqlalchemy python-bson

Install with ``pip``::

    $ sudo pip3 install sqlalchemy bson

There are other optional dependencies that are mostly used by modules and utilities.
The following libraries are not strictly required, but their installation is recommended:

    * `Dpkt`_ (Highly Recommended): for extracting relevant information from PCAP files.
    * `Jinja2`_ (Highly Recommended): for rendering the HTML reports and the web interface.
    * `Magic`_ (Optional): for identifying files' formats (otherwise use "file" command line utility)
    * `Pydeep`_ (Optional): for calculating ssdeep fuzzy hash of files.
    * `Pymongo`_ (Optional): for storing the results in a MongoDB database.
    * `elasticsearch`_ (Optional): For storing and querying data into ElasticSearch
    * `Yara`_ and Yara Python (Optional): for matching Yara signatures (release >=3.0).
    * `Libvirt`_ (Optional): for using the KVM machine manager.
    * `Bottlepy`_ (Optional): for using the ``api.py`` or ``web.py`` utility (release >=0.10).
    * `Django`_ (Optional): for using the web interface (release >=1.5).
    * `Pefile`_ (Optional): used for static analysis of PE32 binaries.
    * `Volatility`_ (Optional): used for forensic analysis on memory (release >=2.4)
    * `MAEC Python bindings`_ (Optional): used for MAEC reporting (use a release >=4.1.0.11, but <5.x).
    * `Chardet`_ (Optional): used for detecting string encoding.
    * `clamd`_ (Optional): for scanning artifacts with ClamAV (release >= 0.3.3)
    * `m2crypto`_ (Optional): for extracting PE digital certificate information
    * `django-ratelimit`_ (Optional): required if using the Django web interface
    * `weasyprint`_ (Optional): can be used for PDF reporting method, but is significantly slower than wkhtmltopdf
    * `pype32`_ (Optional): needed for some RAT decoders
    * `rarfile`_ (Optional): needed for automatic extraction of RAR files on submission
    * `jsbeautifier`_ (Optional): needed for analysis of JavaScript in PDFs
    * `mono-utils`_ (Optional): needed for .NET static analysis
    * `python-whois`_ (Optional): needed to perform domain whois lookups for URL analyses
    * `bs4`_ (Optional): needed to parse and decode WSF and HTA files

Some of them are already packaged in Debian/Ubuntu and can be installed with the following command::

    $ sudo apt-get install python-dpkt python-jinja2 python-magic python-pymongo python-libvirt python-bottle python-pefile python-chardet swig libssl-dev clamav-daemon python-geoip geoip-database mono-utils

Except for *python-magic*, *python-dpkt* and *python-libvirt*, the others can be installed through ``pip`` too::

    $ sudo pip3 install jinja2 pymongo bottle pefile django chardet pygal m2crypto clamd django-ratelimit pycrypto weasyprint rarfile jsbeautifier python-whois bs4

For faster generation of PDF reports, you should install wkhtmltopdf instead of weasyprint.  To do this on Debian/Ubuntu, just use the following command::

    $ sudo apt-get install wkhtmltopdf xvfb xfonts-100dpi

To have MAEC support, you need to first install the Cybox and then the MAEC libraries::

    $ sudo pip3 install cybox==2.1.0.9
    $ sudo pip3 install maec==4.1.0.11

*Yara* and *Pydeep* will have to be installed manually, so please refer to their websites.

If you want to use KVM it's packaged too and you can install it with the following command::

    $ sudo apt-get install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils

.. _Magic: http://www.darwinsys.com/file/
.. _Dpkt: http://code.google.com/p/dpkt/
.. _Jinja2: http://jinja.pocoo.org/docs/
.. _Pydeep: https://github.com/kbandla/pydeep
.. _Pymongo: http://pypi.python.org/pypi/pymongo/
.. _Yara: http://code.google.com/p/yara-project/
.. _Libvirt: http://www.libvirt.org
.. _Bottlepy: http://www.bottlepy.org
.. _Django: https://www.djangoproject.com/
.. _Pefile: http://code.google.com/p/pefile/
.. _Volatility: https://github.com/volatilityfoundation/
.. _MAEC Python bindings: https://pypi.python.org/pypi/maec/4.1.0.11
.. _Chardet: https://pypi.python.org/pypi/chardet
.. _pygal: http://pygal.org/
.. _clamd: https://pypi.python.org/pypi/clamd
.. _m2crypto: https://pypi.python.org/pypi/M2Crypto
.. _django-ratelimit: https://pypi.python.org/pypi/django-ratelimit
.. _weasyprint: http://www.weasyprint.org
.. _pype32: https://github.com/crackinglandia/pype32
.. _rarfile: https://pypi.python.org/pypi/rarfile
.. _jsbeautifier: https://pypi.python.org/pypi/jsbeautifier
.. _bs4: https://pypi.python.org/pypi/bs4

If you want to use XenServer you'll have to install the *XenAPI* Python package::

    $ sudo pip3 install XenAPI

Virtualization Software
=======================

Despite heavily relying on `VirtualBox`_ in the past, Cuckoo has moved on being
architecturally independent from the virtualization software.
As you will see throughout this documentation, you'll be able to define and write
modules to support any software of your choice.

For the sake of this guide we will assume that you have VirtualBox installed
(which still is the default option), but this does **not** affect anyhow the
execution and general configuration of the sandbox.

You are completely responsible for the choice, configuration and execution of
your virtualization software, therefore please refrain from asking for help on
it in our channels and lists: refer to the software's official documentation
and support.

Assuming you decide to go for VirtualBox, you can get the proper package for
your distribution at the `official download page`_.
The installation of VirtualBox is outside the scope of this documentation, if you
are not familiar with it please refer to the `official documentation`_.

.. _VirtualBox: http://www.virtualbox.org
.. _official download page: https://www.virtualbox.org/wiki/Linux_Downloads
.. _official documentation: https://www.virtualbox.org/wiki/Documentation

Installing Tcpdump
==================

In order to dump the network activity performed by the malware during
execution, you'll need a network sniffer properly configured to capture
the traffic and dump it to a file.

By default Cuckoo adopts `tcpdump`_, the prominent open source solution.

Install it on Ubuntu::

    $ sudo apt-get install tcpdump

Tcpdump requires root privileges, but since you don't want Cuckoo to run as root
you'll have to set specific Linux capabilities to the binary::

    $ sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

You can verify the results of last command with::

    $ getcap /usr/sbin/tcpdump
    /usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip

If you don't have `setcap` installed you can get it with::

    $ sudo apt-get install libcap2-bin

Or otherwise (**not recommended**) do::

    $ sudo chmod +s /usr/sbin/tcpdump

Please keep in mind that even the `setcap` method is definitely not perfectly safe
if the system has other users which are potentially untrusted. We recommend to run
Cuckoo on a dedicated system or a trusted environment where the privileged tcpdump
execution is contained otherwise.

.. _tcpdump: http://www.tcpdump.org

Installing Volatility
=====================

Volatility is an optional tool to do forensic analysis on memory dumps.
In combination with Cuckoo, it can automatically provide additional visibility
into deep modifications in the operating system as well as detect the presence
of rootkit technology that escaped the monitoring domain of Cuckoo's analyzer.

In order to function properly, Cuckoo requires at least version 2.3 of Volatility.
You can get it from the `official repository`_.

See the volatility documentation for detailed instructions on how to install it.

.. _official repository: https://github.com/volatilityfoundation

