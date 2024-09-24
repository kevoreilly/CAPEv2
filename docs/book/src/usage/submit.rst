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

    $ poetry run python utils/submit.py /path/to/binary

*Example*: Submit an URL::

    $ poetry run python utils/submit.py --url http://www.example.com

*Example*: Submit a local binary and specify a higher priority::

    $ poetry run python utils/submit.py --priority 5 /path/to/binary

*Example*: Submit a local binary and specify a custom analysis timeout of
60 seconds::

    $ poetry run python utils/submit.py --timeout 60 /path/to/binary

*Example*: Submit a local binary and specify a custom analysis package::

    $ poetry run python utils/submit.py --package <name of package> /path/to/binary

*Example*: Submit a local binary and specify a custom analysis package and
some options (in this case a command line argument for the malware)::

    $ poetry run python utils/submit.py --package exe --options arguments=--dosomething /path/to/binary.exe

*Example*: Submit a local binary to be run on the virtual machine *cape1*::

    $ poetry run python utils/submit.py --machine cape1 /path/to/binary

*Example*: Submit a local binary to be run on a Windows machine::

    $ poetry run python utils/submit.py --platform windows /path/to/binary

*Example*: Submit a local binary and take a full memory dump of the analysis machine once the analysis is complete::

    $ poetry run python utils/submit.py --memory /path/to/binary

*Example*: Submit a local binary and force the analysis to be executed for the full timeout (disregarding the internal mechanism that CAPE uses to decide when to terminate the analysis)::

    $ poetry run python utils/submit.py --enforce-timeout /path/to/binary

*Example*: Submit a local binary and set the virtual machine clock. The format is %m-%d-%Y %H:%M:%S. If not specified, the current time is used. For example, if we want to run a sample on January 24th, 2001, at 14:41:20::

    $ poetry run python utils/submit.py --clock "01-24-2001 14:41:20" /path/to/binary

*Example*: Submit a sample for Volatility analysis (to reduce side effects of the CAPE hooking, switch it off with *options free=True*)::

    $ poetry run python utils/submit.py --memory --options free=True /path/to/binary

``--options`` Options Available
-------------------------------
- ``filename``: Rename the sample file
- ``name``: This will force family extractor to run, Ex: name=trickbot
- ``curdir``: Change from where execute sample, by default %TEMP%, Ex: curdir=%APPDATA% or
        curdir=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
- ``executiondir``: Sets directory to launch the file from. Need not be the same as the directory of sample file. Defaults to %TEMP% if both executiondir and curdir are not specified. Only supports full paths
- ``free``: Run without monitoring (disables many capabilities) Ex: free=1
- ``force-sleepskip``: Override default sleep skipping behavior:  0 disables all sleep skipping, 1 skips all sleeps.
- ``full-logs``: By default, logs prior to network activity for URL analyses and prior to access of the file in question for non-executable formats are suppressed.  Set to 1 to disable log suppression.
- ``force-flush``: For performance reasons, logs are buffered before being sent back to the result server.  We make every attempt to flush the buffer at critical points including when exceptions occur, but in some rare termination scenarios, logs may be lost.  Set to 1 to force flushing of the log buffers after any non-duplicate API is called, set to 2 to force flushing of every log.
- ``no-stealth``: Set to 1 to disable anti-anti-VM/sandbox code enabled by default.
- ``buffer-max``: When set to an integer of your choice, changes the maximum number of bytes that can be logged for most API buffers.
- ``large-buffer-max``: Some hooked APIs permit larger buffers to be logged.  To change the limit for this, set this to an integer of your choice.
- ``norefer``: Disables use of a fake referrer when performing URL analyses
- ``file``: When using the zip or rar package, set the name of the file to execute
- ``password``: When using the zip or rar package, set the password to use for extraction.  Also used when analyzing password-protected Office documents.
- ``function``: When using the dll package, set the name of the exported function to execute
- ``dllloader``: When using the dll package, set the name of the process loading the DLL (defaults to rundll32.exe).
- ``arguments``: When using the dll, exe, or python packages, set the arguments to be passed to the executable or exported function.
- ``appdata``: When using the exe package, set to 1 to run the executable out of the Application Data path instead of the Temp directory.
- ``startbrowser``: Setting this option to 1 will launch a browser 30 seconds into the analysis (useful for some banking trojans).
- ``browserdelay``: Sets the number of seconds to wait before starting the browser with the startbrowser option.  Defaults to 30 seconds.
- ``url``: When used with the startbrowser option, this will determine the URL the started browser will access.
- ``debug``: Set to 1 to enable reporting of critical exceptions occurring during analysis, set to 2 to enable reporting of all exceptions.
- ``disable_hook_content``: Set to 1 to remove functionality of all hooks except those critical for monitoring other processes.  Set to 2 to apply to all hooks.
- ``hook-type``: Valid for 32-bit analyses only.  Specifies the hook type to use: direct, indirect, or safe.  Safe attempts a Detours-style hook.
- ``serial``: Spoof the serial of the system volume as the provided hex value
- ``single-process``: When set to 1 this will limit behavior monitoring to the initial process only.
- ``exclude-apis``: Exclude the colon-separated list of APIs from being hooked
- ``exclude-dlls``: Exclude the colon-separated list of DLLs from being hooked
- ``dropped-limit``: Override the default dropped file limit of 100 files
- ``compression``: When set to 1 this will enable CAPE's extraction of compressed payloads
- ``extraction``: When set to 1 this will enable CAPE's extraction of payloads from within each process
- ``injection``: When set to 1 this will enable CAPE's capture of injected payloads between processes
- ``combo``: This combines compression, injection and extraction with process dumps
- ``dump-on-api``: Dump the calling module when a function from the colon-separated list of APIs is used
- ``bp0``: Sets breakpoint 0 (processor/hardware) to a VA or RVA value (or module::export). Applies also to bp1-bp3.
- ``file-offsets``: Breakpoints in bp0-bp3 will be interpreted as PE file offsets rather than RVAs
- ``break-on-return``: Sets breakpoints on the return address(es) from a colon-separated list of APIs
- ``base-on-api``: Sets the base address to which breakpoints will be applied (and sets breakpoints)
- ``depth``: Sets the depth an instruction trace will step into (defaults to 0, requires Trace package)
- ``count``: Sets the number of instructions in a trace (defaults to 128, requires Trace package)
- ``referrer``: Specify the referrer to be used for URL tasks, overriding the default Google referrer
- ``loop_detection``: Set this option to 1 to enable loop detection (compress call logs - behavior analysis)
- ``static``: Check if config can be extracted statically, if not, send to vm
- ``Dl&Exec add headers``: Example: dnl_user_agent: "CAPE Sandbox", dnl_referrer: google
- ``servicedesc`` - for service package: Service description
- ``arguments`` - for service package: Service arguments
- ``store_memdump``: Will force STORE memdump, only when submitting to analyzer node directly, as distributed cluster can modify this
- ``pre_script_args``: Command line arguments for pre_script. Example: pre_script_args=file1 file2 file3
- ``pre_script_timeout``: pre_script_timeout will default to 60 seconds. Script will stop after timeout Example: pre_script_timeout=30
- ``during_script_args``: Command line arguments for during_script. Example: during_script_args=file1 file2 file3
- ``pwsh``: - for ps1 package: prefer PowerShell Core, if available in the vm
- ``check_shellcode``: - Setting check_shellcode=0 will disable checking for shellcode during package identification and extracting from archive
- ``unhook-apis``: - capability to dynamically unhook previously hooked functions (unhook-apis option takes colon-separated list e.g. unhook-apis=NtSetInformationThread:NtDelayExecution)
- ``ttd``: - ttd=1. TTD integration (Microsoft Time Travel Debugging). Place TTD binaries in analyzer/windows/bin (with wow64 subdirectory for 32-bit). .trc files output to TTD directory in results folder for manual retrieval

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

    $ sudo -u cape poetry run python submit.py /path/to/binary/test.exe
    Error: adding task to database

It could be due to errors while trying to communicate with the PostgreSQL instance. PostgreSQL is installed and configured by default when executing ``cape2.sh``. Make sure your PostgreSQL instance is active and running. To check it out execute the following command::

    $ sudo systemctl status postgresql

If the status is other than **Active** (it can be in exited status, as long as it is Active), there is something that needs to be fixed.

The logs for PostgreSQL can be found under */var/log/postgresql/\*.log*.

If everything is working regarding PostgreSQL, **make sure** the ``cape`` user is able to access (both read and write) the directories involved in the analysis. For example, ``cape`` must be able to read and write in */tmp*.

Analysis results
================

Check :ref:`analysis_results`.
