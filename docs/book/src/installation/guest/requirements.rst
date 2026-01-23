============
Requirements
============

To make CAPE run properly in your virtualized Windows system, you
will have to install some required software and libraries.

Install Python
==============

Python is a strict requirement for the CAPE guest component (*analyzer*) to run properly.

.. warning::
    Please note that **only 32-bit (x86) versions of Python3 are
    supported** at this time for Windows, due to the way the analyzer
    interacts with low-level Windows libraries. Using a 64-bit version
    of Python will crash the analyzer in Windows. For other platforms the
    version of Python can be 64-bit (x64).

You can download the proper `Windows`_ / `Linux`_ installer from the `official website`_.
Python versions > 3.10 and < 3.13 are preferred.

.. important::
    When installing Python, it is recommended to select the `Add Python <version> to PATH` option. And remove from that PATH `%USERPROFILE%\AppData\Local\Microsoft\WindowsApps`

    .. image:: ../../_images/screenshots/python_guest_win10_installation_PATH.png
        :align: center

When the installation is done, it is recommended to test whether Python is correctly set into your PATH environment variable. In order to do so, you can execute the following commands from a command prompt::

> python --version

You should be prompted with Python's installed version. **If not**, make sure you add the binaries to your PATH. There are tutorials galore on the Internet.

Some Python libraries are optional and provide some additional features to the
CAPE guest component. They include:

    * `Python Image Library`_: used for taking screenshots of the Windows desktop during the analysis.

    The recommended installation is the execution of the following commands::

    > python -m pip install --upgrade pip
    > python -m pip install Pillow

These Python libraries are not strictly required by CAPE, but you are encouraged
to install them if you want to have access to all available features. Make sure
to download and install the proper packages according to your Python version.

.. _`Windows`: https://www.python.org/downloads/windows/
.. _`Linux`: https://www.python.org/downloads/source/
.. _`official website`: http://www.python.org/getit/
.. _`Python Image Library`: https://python-pillow.org

Additional Software
===================

At this point, you should have installed everything needed by CAPE to run
properly.

Depending on what kind of files you want to analyze and what kind of sandbox
environment you want to run the malware samples in, you may want to install
additional software such as browsers, PDF readers, office suites, etc.

.. note::

    Remember to disable the "Auto Update" or "Check For Updates" feature of
    any additional software that you install.

    For Microsoft Office we recommend Office 2010 SP2. This is both for its
    susceptibility to exploits typically used in maldocs, and its proven
    compatibility with CAPE. The only recommended alternative is Office 2016
    (32-bit).

    We do not recommend any Office version more recent than 2016 due to lack
    of proven compatibility with both maldocs and CAPE.

For hints about what your needs may be, give the :doc:`../../introduction/sandboxing` chapter a read.

.. _`choco.bat`: https://github.com/kevoreilly/CAPEv2/blob/master/installer/choco.bat
.. _`disablewin7noise.bat`:  https://github.com/kevoreilly/CAPEv2/blob/master/installer/disable_win7noise.bat
