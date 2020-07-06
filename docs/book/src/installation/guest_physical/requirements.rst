============
Requirements
============

In order to make CAPE run properly in your physical Windows system, you
will have to install some required software and libraries.

Install Python
==============

Python is a strict requirement for the CAPE guest component (*analyzer*) in
order to run properly.

You can download the proper Windows installer from the `official website`_.
Also in this case Python > 3.6 is preferred.

Some Python libraries are optional and provide some additional features to
CAPE guest component. They include:

    * `Python Image Library`_: it's used for taking screenshots of the Windows desktop during the analysis.

They are not strictly required by CAPE to work properly, but you are encouraged
to install them if you want to have access to all available features. Make sure
to download and install the proper packages according to your Python version.

.. _`official website`: http://www.python.org/getit/
.. _`Python Image Library`: https://python-pillow.org

Additional Software
===================

At this point you should have installed everything needed by CAPE to run
properly.

Depending on what kind of files you want to analyze and what kind of sandboxed
Windows environment you want to run the malware samples in, you might want to install
additional software such as browsers, PDF readers, office suites etc.
Remember to disable the "auto update" or "check for updates" feature of
any additional software.

This is completely up to you and to what your needs are. You can get some hints
by reading the :doc:`../../introduction/sandboxing` chapter.


Additional Host Requirements
============================
The physical machine manager uses RPC requests to reboot physical machines.
  The `net` command is required for this to be accomplished, and is available
  from the samba-common-bin package.

On Debian/Ubuntu:

    $ sudo apt-get install samba-common-bin

In order for the physical machine manager to work, you must have a way
for physical machines to be returned to a clean state.  In development/testing
Fog (`http://www.fogproject.org/`_) was used as a platform to handle re-imaging
the physical machines.  However, any re-imaging platform can be used
(Clonezilla, Deepfreeze, etc) to accomplish this.

.. _`http://www.fogproject.org/`: http://www.fogproject.org/

Some extras by doomedraven:
.. _`choco.bat`: https://github.com/doomedraven/Tools/blob/master/Windows/choco.bat
.. _`disablewin7noise.bat`: https://github.com/doomedraven/Tools/blob/master/Windows/disable_win7noise.bat
