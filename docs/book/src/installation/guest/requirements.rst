============
Requirements
============

To make CAPE run properly in your virtualized Windows system, you
will have to install some required software and libraries.

Install Python
==============

Python is a strict requirement for the CAPE guest component (*analyzer*) to run properly.  Please note that only 32-bit versions of Python3 are
supported at this time.

You can download the proper Windows installer from the `official website`_.
Also in this case Python > 3.6 is preferred.

Some Python libraries are optional and provide some additional features to the
CAPE guest component. They include:

    * `Python Image Library`_: it's used for taking screenshots of the Windows desktop during the analysis.

They are not strictly required by CAPE to work properly, but you are encouraged
to install them if you want to have access to all available features. Make sure
to download and install the proper packages according to your Python version.

.. _`official website`: http://www.python.org/getit/
.. _`Python Image Library`: https://python-pillow.org

Additional Software
===================

At this point, you should have installed everything needed by CAPE to run
properly.

Depending on what kind of files you want to analyze and what kind of sandboxed
Windows environment you want to run the malware samples in, you might want to install
additional software such as browsers, PDF readers, office suites, etc.
Remember to disable the "auto update" or "check for updates" feature of
any additional software.

This is completely up to you and what your needs are. You can get some hints
by reading the :doc:`../../introduction/sandboxing` chapter.

Something extra to consider from doomedraven ;)

.. _`choco.bat`: https://github.com/doomedraven/Tools/blob/master/Windows/choco.bat
.. _`disablewin7noise.bat`: https://github.com/doomedraven/Tools/blob/master/Windows/disable_win7noise.bat
