==================
Submit an Analysis
==================

    * :ref:`submitpy`
    * :ref:`apipy`
    * :ref:`distpy`
    * :ref:`webpy`
    * :ref:`python`

.. _submitpy:

Submission Utility
==================

The easiest way to submit an analysis is to use the provided *submit.py*
command-line utility. It currently has the following options available::

    usage: submit.py [-h] [--remote REMOTE] [--url] [--package PACKAGE]
                     [--custom CUSTOM] [--timeout TIMEOUT] [--options OPTIONS]
                     [--priority PRIORITY] [--machine MACHINE]
                     [--platform PLATFORM] [--memory] [--enforce-timeout]
                     [--clock CLOCK] [--tags TAGS] [--max MAX] [--pattern PATTERN]
                     [--shuffle] [--unique] [--quiet]
                     target

    positional arguments:
      target               URL, path to the file or folder to analyze

    optional arguments:
      -h, --help           show this help message and exit
      --remote REMOTE      Specify IP:port to a CAPE API server to submit
                           remotely
      --url                Specify whether the target is an URL
      --package PACKAGE    Specify an analysis package
      --custom CUSTOM      Specify any custom value
      --timeout TIMEOUT    Specify an analysis timeout
      --options OPTIONS    Specify options for the analysis package (e.g.
                           "name=value,name2=value2")
      --priority PRIORITY  Specify a priority for the analysis represented by an
                           integer
      --machine MACHINE    Specify the identifier of a machine you want to use
      --platform PLATFORM  Specify the operating system platform you want to use
                           (windows/darwin/linux)
      --memory             Enable to take a memory dump of the analysis machine
      --enforce-timeout    Enable to force the analysis to run for the full
                           timeout period
      --clock CLOCK        Set virtual machine clock
      --tags TAGS          Specify tags identifier of a machine you want to use
      --max MAX            Maximum samples to add in a row
      --pattern PATTERN    Pattern of files to submit
      --shuffle            Shuffle samples before submitting them
      --unique             Only submit new samples, ignore duplicates
      --quiet              Only print text on failure

If you specify a directory as the target path, all of the files contained within that directory will be
submitted for analysis.

The concept of analysis packages will be dealt with later in this documentation (at
:doc:`packages`). The following are some examples of how to use the `submit.py` tool:

    .. warning:: Remember to use the ``cape`` user. The following commands are executed as ``cape``.

*Example*: Submit a local binary::

    $ ./utils/submit.py /path/to/binary

*Example*: Submit an URL::

    $ ./utils/submit.py --url http://www.example.com

*Example*: Submit a local binary and specify a higher priority::

    $ ./utils/submit.py --priority 5 /path/to/binary

*Example*: Submit a local binary and specify a custom analysis timeout of
60 seconds::

    $ ./utils/submit.py --timeout 60 /path/to/binary

*Example*: Submit a local binary and specify a custom analysis package::

    $ ./utils/submit.py --package <name of package> /path/to/binary

*Example*: Submit a local binary and specify a custom analysis package and
some options (in this case a command line argument for the malware)::

    $ ./utils/submit.py --package exe --options arguments=--dosomething /path/to/binary.exe

*Example*: Submit a local binary to be run on the virtual machine *cape1*::

    $ ./utils/submit.py --machine cape1 /path/to/binary

*Example*: Submit a local binary to be run on a Windows machine::

    $ ./utils/submit.py --platform windows /path/to/binary

*Example*: Submit a local binary and take a full memory dump of the analysis machine once the analysis is complete::

    $ ./utils/submit.py --memory /path/to/binary

*Example*: Submit a local binary and force the analysis to be executed for the full timeout (disregarding the internal mechanism that CAPE uses to decide when to terminate the analysis)::

    $ ./utils/submit.py --enforce-timeout /path/to/binary

*Example*: Submit a local binary and set the virtual machine clock. The format is %m-%d-%Y %H:%M:%S. If not specified, the current time is used. For example, if we want to run a sample on January 24th, 2001, at 14:41:20::

    $ ./utils/submit.py --clock "01-24-2001 14:41:20" /path/to/binary

*Example*: Submit a sample for Volatility analysis (to reduce side effects of the CAPE hooking, switch it off with *options free=True*)::

    $ ./utils/submit.py --memory --options free=True /path/to/binary

.. _webpy:

Web Interface
=============

Detailed usage of the web interface is described in :doc:`web`.

.. _apipy:

API
===

Detailed usage of the REST API interface is described in :doc:`api`.

.. _distpy:

Distributed CAPE
==================

Detailed usage of the Distributed CAPE API interface is described in
:doc:`dist`.

.. _python:

Python Functions
================

To keep track of submissions, samples, and overall execution, CAPE
uses a popular Python ORM called `SQLAlchemy`_ that allows you to make the sandbox
use PostgreSQL, SQLite, MySQL, and several other SQL database systems.

CAPE is designed to be easily integrated into larger solutions and to be fully
automated. To automate analysis submission we suggest using the REST
API interface described in :doc:`api`, but in case you want to write a
Python submission script, you can also use the ``add_path()`` and ``add_url()`` functions.

.. function:: add_path(file_path[, timeout=0[, package=None[, options=None[, priority=1[, custom=None[, machine=None[, platform=None[, memory=False[, enforce_timeout=False], clock=None[]]]]]]]]])

    Add a local file to the list of pending analysis tasks. Returns the ID of the newly generated task.

    :param file_path: path to the file to submit
    :type file_path: string
    :param timeout: maximum amount of seconds to run the analysis for
    :type timeout: integer
    :param package: analysis package you want to use for the specified file
    :type package: string or None
    :param options: list of options to be passed to the analysis package (in the format ``key=value,key=value``)
    :type options: string or None
    :param priority: numeric representation of the priority to assign to the specified file (1 being low, 2 medium, 3 high)
    :type priority: integer
    :param custom: custom value to be passed over and possibly reused at processing or reporting
    :type custom: string or None
    :param machine: CAPE identifier of the virtual machine you want to use, if none is specified one will be selected automatically
    :type machine: string or None
    :param platform: operating system platform you want to run the analysis one (currently only Windows)
    :type platform: string or None
    :param memory: set to ``True`` to generate a full memory dump of the analysis machine
    :type memory: True or False
    :param enforce_timeout: set to ``True`` to force the execution for the full timeout
    :type enforce_timeout: True or False
    :param clock: provide a custom clock time to set in the analysis machine
    :type clock: string or None
    :rtype: integer

    Example usage:

    .. code-block:: python
        :linenos:

        >>> from lib.cuckoo.core.database import Database
        >>> db = Database()
        >>> db.add_path("/tmp/malware.exe")
        1
        >>>

.. function:: add_url(url[, timeout=0[, package=None[, options=None[, priority=1[, custom=None[, machine=None[, platform=None[, memory=False[, enforce_timeout=False], clock=None[]]]]]]]]])

    Add a local file to the list of pending analysis tasks. Returns the ID of the newly generated task.

    :param url: URL to analyze
    :type url: string
    :param timeout: maximum amount of seconds to run the analysis for
    :type timeout: integer
    :param package: analysis package you want to use for the specified URL
    :type package: string or None
    :param options: list of options to be passed to the analysis package (in the format ``key=value,key=value``)
    :type options: string or None
    :param priority: numeric representation of the priority to assign to the specified URL (1 being low, 2 medium, 3 high)
    :type priority: integer
    :param custom: custom value to be passed over and possibly reused at processing or reporting
    :type custom: string or None
    :param machine: CAPE identifier of the virtual machine you want to use, if none is specified one will be selected automatically
    :type machine: string or None
    :param platform: operating system platform you want to run the analysis one (currently only Windows)
    :type platform: string or None
    :param memory: set to ``True`` to generate a full memory dump of the analysis machine
    :type memory: True or False
    :param enforce_timeout: set to ``True`` to force the execution for the full timeout
    :type enforce_timeout: True or False
    :param clock: provide a custom clock time to set in the analysis machine
    :type clock: string or None
    :rtype: integer

Example Usage:

.. code-block:: python
    :linenos:

    >>> from lib.cuckoo.core.database import Database
    >>> db = Database()
    >>> db.add_url("http://www.cuckoosandbox.org")
    2
    >>>

.. _`SQLAlchemy`: http://www.sqlalchemy.org

Troubleshooting
===============

submit.py
---------

If you try to submit an analysis using ``submit.py`` and your output looks like::

    $ sudo -u cape poetry run python3 submit.py /path/to/binary/test.exe
    Error: adding task to database

It could be due to errors while trying to communicate with the PostgreSQL instance. PostgreSQL is installed and configured by default when executing ``cape2.sh``. Make sure your PostgreSQL instance is active and running. To check it out execute the following command::

    $ sudo systemctl status postgresql

If the status is other than **Active** (it can be in exited status, as long as it is Active), there is something that needs to be fixed.

The logs for PostgreSQL can be found under */var/log/postgresql/\*.log*. 

If everything is working regarding PostgreSQL, **make sure** the ``cape`` user is able to access (both read and write) the directories involved in the analysis. For example, ``cape`` must be able to read and write in */tmp*.

Analysis results
================

Check :ref:`analysis_results`.