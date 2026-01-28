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

Analysis options can be specified at submission time in the format ``option1=val1,option2=val2``. These options control the behavior of the monitor and analyzer during detonation.

Submission & General
^^^^^^^^^^^^^^^^^^^^
- ``filename``: Rename the sample file within the guest environment.
- ``name``: Force family extractor to run for a specific family (e.g., ``name=trickbot``).
- ``curdir``: Change the execution directory (default is ``%TEMP%``). Supports environment variables like ``%APPDATA%``.
- ``executiondir``: Sets the directory to launch the file from. Must be a full path.
- ``arguments``: Command line arguments to pass to the initial process or exported function.
- ``appdata``: Set to ``1`` to run the executable from the ``AppData`` path instead of ``Temp``.
- ``file``: For Zip/Rar packages, specify which file within the archive to execute.
- ``password``: Password for archive extraction or protected Office documents.
- ``function``: For DLL packages, specify exported function name(s) or ordinals (colon-separated).
- ``dllloader``: Specify a process name to fake the DLL launcher (default is ``rundll32.exe``).
- ``pwsh``: For PS1 package, prefer PowerShell Core (``pwsh.exe``) if available.
- ``ignore_size_check``: Allow ignoring file size limits (must be enabled in ``conf/web.conf``).
- ``check_shellcode``: Set to ``0`` to disable shellcode detection during package identification.
- ``pre_script_args`` / ``during_script_args``: Command line arguments for pre/during-execution scripts.
- ``pre_script_timeout``: Timeout for pre-execution script (default 60s).
- ``servicedesc`` / ``servicename``: Custom name and description for Service packages.
- ``lang``: Override the system language code (LCID).
- ``standalone``: Run in standalone mode without a Cuckoo pipe.
- ``monitor``: Inject the monitor into a specific PID or explorer (useful for interactive mode).
- ``shutdown-mutex``: Name of the mutex that signals a shutdown/termination.
- ``terminate-event``: Name of the event set by the analyzer to signal termination.
- ``terminate-processes``: If true, terminate processes when ``terminate-event`` is signaled.
- ``first-process``: (Internal) Flag indicating if this is the first process in the analysis tree.
- ``startup-time``: Milliseconds since system startup.

Monitor & Evasion
^^^^^^^^^^^^^^^^^
- ``free``: Run without monitoring (disables many capabilities for stealth or performance).
- ``no-stealth``: Set to ``1`` to disable built-in anti-anti-VM/sandbox tricks.
- ``force-sleepskip``: ``0`` = disable sleep skipping, ``1`` = skip all sleeps.
- ``serial``: Spoof the system volume serial number (Hex value).
- ``sysvol_ctimelow/high``: Spoof the creation time of the system volume.
- ``sys32_ctimelow/high``: Spoof the creation time of the System32 directory.
- ``fake-rdtsc``: Enable fake RDTSC (Read Time-Stamp Counter) results.
- ``nop-rdtscp``: NOP the RDTSCP instruction.
- ``ntdll-protect``: Enable write protection on ``ntdll.dll`` code.
- ``ntdll-unhook``: Enable protection against ntdll unhooking via ``NtReadFile``.
- ``ntdll-remap``: Enable ntdll remapping protection.
- ``protected-pids``: Enable protection for critical PIDs to prevent termination or injection.
- ``single-process``: Limit behavior monitoring to the initial process only.
- ``interactive``: Enable interactive desktop mode.
- ``pdf``: Enable specific hooks/behavior for Adobe Reader.
- ``startbrowser``: Launch a browser 30 seconds into the analysis.
- ``browserdelay``: Seconds to wait before starting the browser (default 30).
- ``url``: Determine the URL the started browser will access.
- ``referrer``: Specify a custom referrer for URL tasks.
- ``norefer``: Disable the use of a fake referrer.
- ``file-of-interest``: Specify a particular file or URL being analyzed.

Hooking & Logging
^^^^^^^^^^^^^^^^^
- ``hook-type``: Hooking method: ``indirect``, ``pushret``, ``direct``, or ``safe``.
- ``hook-range``: Limit the number of applied hooks (useful for testing).
- ``hook-low``: Allocate hook trampolines in low memory (<2GB) on x64 systems.
- ``hook-restore``: Attempt to restore hooks if modification is detected.
- ``hook-protect``: Enable write protection on hook pages.
- ``hook-watch``: Enable continuous monitoring of hook integrity.
- ``disable-hook-content``: ``1`` = remove payload of non-critical hooks, ``2`` = remove payload of all hooks.
- ``minhook`` / ``zerohook``: Enable only minimal hooks or disable all non-essential hooks.
- ``native``: Install only native (ntdll) hooks.
- ``syscall``: Enable syscall hooks (Windows 10+).
- ``exclude-apis`` / ``exclude-dlls``: Colon-separated lists of APIs or DLLs to exclude from hooking.
- ``unhook-apis``: Colon-separated list of APIs to dynamically unhook at runtime.
- ``coverage-modules``: Colon-separated list of DLLs to include in monitoring (exclude from 'dll range' filtering).
- ``full-logs``: Disable log suppression (logs before network/file activity are normally suppressed).
- ``force-flush``: ``1`` = flush logs after any non-duplicate API, ``2`` = force flush every log.
- ``log-exceptions`` / ``log-vexcept``: Enable logging of standard or Vectored Exception Handlers.
- ``log-breakpoints`` / ``log-bps``: Enable logging of breakpoints to the behavior log.
- ``trace-times`` / ``tt``: Enable timing information in instruction traces.
- ``buffer-max`` / ``large-buffer-max``: Max size for standard and large API log buffers.
- ``api-rate-cap`` / ``api-cap``: Limits for the rate and total number of API logs.
- ``no-logs`` / ``disable-logging``: Divert or completely disable the analysis log.

Dumping & Payloads
^^^^^^^^^^^^^^^^^^
- ``procdump``: Enable process memory dumping on exit or timeout.
- ``procmemdump``: Enable full process memory dumping.
- ``import-reconstruction``: Attempt import reconstruction on process dumps (slow).
- ``dump-limit``: Limit the number of payload dumps (default 10).
- ``dropped-limit``: Limit the number of dropped files logged (default 100).
- ``dump-on-api``: Dump the calling module when specific APIs (colon-separated) are called.
- ``dump-config-region``: Dump memory regions suspected to contain C2 configuration.
- ``dump-crypto`` / ``dump-keys``: Dump buffers from Crypto APIs or keys from ``CryptImportKey``.
- ``amsidump``: Enable AMSI buffer dumping (Windows 10+).
- ``jit-dumps``: Limit for .NET JIT cache dumps.
- ``tlsdump``: Enable dumping of TLS secrets.
- ``regdump``: Enable dumping of Registry data.
- ``unpacker``: ``1`` = passive unpacking, ``2`` = active unpacking.
- ``injection`` / ``extraction`` / ``compression``: Enable capture of injected payloads, process extractions, or compressed payloads.
- ``combo``: Combines compression, injection, and extraction with process dumps.
- ``store_memdump``: Force STORE memdump when submitting to an analyzer node directly.

Debug & Tracing
^^^^^^^^^^^^^^^
- ``debugger``: Enable the internal debugger engine (implicitly set by bp/trace options).
- ``debug``: ``1`` = report critical exceptions, ``2`` = report all exceptions.
- ``bp0``...``bp3``: Set hardware breakpoints (format: ``0xAddress``, ``Module:Export``, or ``ep`` for entrypoint).
- ``br0``, ``br1``: Set "break-on-return" addresses.
- ``bp`` / ``sysbp``: Colon-separated lists of software or syscall breakpoints.
- ``sysbpmode``: Mode for syscall breakpoints.
- ``break-on-return``: Colon-separated list of APIs to break on return.
- ``break-on-jit``: Break on .NET JIT compiled native code.
- ``trace-all``: Enable full execution tracing.
- ``trace-into-api``: Colon-separated list of APIs to trace into.
- ``branch-trace``: Enable branch tracing.
- ``depth``: Trace depth limit (integer or ``all``).
- ``count``: Trace instruction count limit (integer or ``all``).
- ``step-out``: Set a step-out breakpoint at a specific address.
- ``stepmode``: Custom trace stepping behavior.
- ``loopskip`` / ``loop_detection``: Enable loop skipping or detection to compress call logs.
- ``base-on-api``: Base breakpoints on specific API addresses.
- ``base-on-alloc``: Base breakpoints on executable memory allocations.
- ``base-on-caller``: Base breakpoints on new calling regions.
- ``file-offsets``: Interpret breakpoints as file offsets instead of RVAs.
- ``loaderlock``: Allow scans/dumps while the Loader Lock is held.
- ``snaps``: Enable Windows Loader Snaps output (LdrSnap).
- ``ttd``: Enable Microsoft Time Travel Debugging integration (requires TTD binaries).
- ``polarproxy``: Run PolarProxy for TLS decryption (TLS port can be set via ``tlsport``).
- ``mitmdump``: Run mitmdump to generate HAR with decrypted TLS.

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
