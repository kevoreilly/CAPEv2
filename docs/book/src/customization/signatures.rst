==========
Signatures
==========

By taking advantage of CAPE's customizability, you can write signatures which will then
by run against analysis results. These signatures can be used to identify a predefined
pattern that represents a malicious behavior or an indicator that you're interested in.

These signatures are very useful to give context to the analyses. They
simplify the interpretation of the results and assist with automatically identifying
malware samples of interest.

A few examples of what you can use CAPE's signatures for are:
    * Identify a particular malware family that you're interested in, by isolating unique behaviors (like file names or mutexes).
    * Spot interesting modifications that the malware performs on the system, such as the installation of device drivers.
    * Identify particular malware categories, such as Banking Trojans or Ransomware, by isolating typical actions that are commonly performed by these categories.

You can find signatures created by the CAPE administrators and other CAPE users on the `Community`_ repository.

.. _`Community`: https://github.com/kevoreilly/community

Getting Started
===============

Creating a signature is a very simple process but requires a decent
understanding of Python programming.

First things first, all signatures must be located inside the *modules/signatures/* directory.

The following is a basic example signature:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

        class CreatesExe(Signature):
            name = "creates_exe"
            description = "Creates a Windows executable on the filesystem"
            severity = 2
            categories = ["generic"]
            authors = ["CAPE Developers"]
            minimum = "0.5"

            def run(self):
                return self.check_file(pattern=".*\\.exe$",
                                       regex=True)

As you can see the structure of the signature is really simple and consistent with the other CAPE
modules. Note that on line **12** a helper function is used. These helper functions
assist with signature-writing and we highly recommend becoming familiar with what helper functions are
available to you (found in the
[Signature class](https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/common/abstracts.py))
before you start writing signatures. Some documentation for :ref:`Helpers` can be found below.

In the example above, the helper function is used to walk through all of the accessed files in the summary and check
if there are any files ending with "*.exe*". If there is at least one, then the helper function will return ``True``;
otherwise it will return ``False``. When a signature returns True, that means that the signature matched.

If the signature matches, a new entry in the "signatures" section will be added to
the **global container** `self.results` as follows::

    "signatures": [
        {
            "severity": 2,
            "description": "Creates a Windows executable on the filesystem",
            "alert": false,
            "references": [],
            "data": [
                {
                    "file_name": "C:\\d.exe"
                }
            ],
            "name": "creates_exe"
        }
    ]

We could rewrite the exact same signature by accessing the **global container**
directly, rather than through the helper function `check_file`:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

        class CreatesExe(Signature):
            name = "creates_exe"
            description = "Creates a Windows executable on the filesystem"
            severity = 2
            categories = ["generic"]
            authors = ["Cuckoo Developers"]
            minimum = "0.5"

            def run(self):
                for file_path in self.results["behavior"]["summary"]["files"]:
                    if file_path.endswith(".exe"):
                        return True

                return False

If you access the **global container** directly, you must know its structure,
which can be observed in the JSON report of your analyses.

Creating your new signature
===========================

To help you better understand the process of creating a signature, we
are going to create a very simple one together and walk through the steps and
the available options. For this purpose, we're going to create a
signature that checks whether the malware analyzed opens a mutex named
"i_am_a_malware".

The first thing to do is to import the dependencies, create a skeleton, and define
some initial attributes. These are the attributes that you can currently set:

    * ``name``: an identifier for the signature.
    * ``description``: a brief description of what the signature represents.
    * ``severity``: a number identifying the severity of the events matched (generally between 1 and 3).
    * ``confidence``: a number between 1 and 100 that represents how confident the signature writer is that this signature will not be raised as a false positive.
    * ``weight``: a number used for calculating the `malscore` of a submission. This attribute acts as a multiplier of the product of severity and confidence.
    * ``categories``: a list of categories that describe the type of event being matched (for example "*banker*", "*injection*" or "*anti-vm*"). For a list of all categories, see :ref:`Categories`.
    * ``families``: a list of malware family names, in case the signature specifically matches a known one.
    * ``authors``: a list of people who authored the signature.
    * ``references``: a list of references (URLs) to give context to the signature.
    * ``enabled``: if set to False the signature will be skipped.
    * ``alert``: if set to True can be used to specify that the signature should be reported (perhaps by a dedicated reporting module).
    * ``minimum``: the minimum required version of CAPE to successfully run this signature.
    * ``maximum``: the maximum required version of CAPE to successfully run this signature.
    * ``ttps``: a list of MITRE ATT&CK IDs applicable to this signature.
    * ``mbcs``: a list of MITRE Malware Behavior Catalog IDs applicable to this signature.

In our example, we will create the following skeleton:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

        class BadBadMalware(Signature): # We initialize the class by inheriting Signature.
            name = "badbadmalware" # We define the name of the signature
            description = "Creates a mutex known to be associated with Win32.BadBadMalware" # We provide a description
            severity = 3 # We set the severity to maximum
            categories = ["trojan"] # We add a category
            families = ["badbadmalware"] # We add the name of our fictional malware family
            authors = ["Me"] # We specify the author
            minimum = "0.5" # We specify that in order to run the signature, the user will need at least CAPE 0.5

        def run(self):
            return

This is a perfectly valid signature. It doesn't do anything yet,
so now we need to define the conditions for the signature to be matched.

Since we want to match a particular mutex name, we use the helper function `check_mutex`:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

        class BadBadMalware(Signature):
            name = "badbadmalware"
            description = "Creates a mutex known to be associated with Win32.BadBadMalware"
            severity = 3
            categories = ["trojan"]
            families = ["badbadmalware"]
            authors = ["Me"]
            minimum = "0.5"

        def run(self):
            return self.check_mutex("i_am_a_malware")

It's as simple as that! Now our signature will return ``True`` if the analyzed
malware was observed opening the specified mutex.

If you want to be more explicit and directly access the **global container**,
you could translate the previous signature in the following way:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

        class BadBadMalware(Signature):
            name = "badbadmalware"
            description = "Creates a mutex known to be associated with Win32.BadBadMalware"
            severity = 3
            categories = ["trojan"]
            families = ["badbadmalware"]
            authors = ["Me"]
            minimum = "0.5"

        def run(self):
            for mutex in self.results["behavior"]["summary"]["mutexes"]:
                if mutex == "i_am_a_malware":
                    return True

            return False

Evented Signatures
==================

Since version 1.0, CAPE provides a way to write more high-performance signatures.
In the past, every signature was required to loop through the whole collection of API calls
collected during the analysis. This was necessarily causing some performance issues when such
a collection would be large.

CAPE now supports both the old model as well as what we call "evented signatures".
The main difference is that with this new format, all the signatures will be executed in parallel
and a callback function called ``on_call()`` will be invoked for each signature within one
single loop through the collection of API calls.

An example signature using this technique is the following:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

        class SystemMetrics(Signature):
            name = "generic_metrics"
            description = "Uses GetSystemMetrics"
            severity = 2
            categories = ["generic"]
            authors = ["CAPE Developers"]
            minimum = "1.0"

            # Evented signatures need to implement the "on_call" method
            evented = True

            # Evented signatures can specify filters that reduce the amount of
            # API calls that are streamed in. One can filter Process name, API
            # name/identifier and category. These should be sets for faster lookup.
            filter_processnames = set()
            filter_apinames = set(["GetSystemMetrics"])
            filter_categories = set()

            # This is a signature template. It should be used as a skeleton for
            # creating custom signatures, therefore is disabled by default.
            # The on_call function is used in "evented" signatures.
            # These use a more efficient way of processing logged API calls.
            enabled = False

            def stop(self):
                # In the stop method one can implement any cleanup code and
                #  decide one last time if this signature matches or not.
                #  Return True in case it matches.
                return False

            # This method will be called for every logged API call by the loop
            # in the RunSignatures plugin. The return value determines the "state"
            # of this signature. True means the signature matched and False means
            # it can't match anymore. Both of which stop streaming in API calls.
            # Returning None keeps the signature active and will continue.
            def on_call(self, call, process):
                # This check would in reality not be needed as we already make use
                # of filter_apinames above.
                if call["api"] == "GetSystemMetrics":
                    # Signature matched, return True.
                    return True

                # continue
                return None

The inline comments are already self-explanatory.
You can find many more examples of both evented and traditional signatures in our `community repository`_.

.. _`community repository`: https://github.com/kevoreilly/community

Matches
=======

Starting from version 1.2, signatures can log exactly what triggered
the signature. This allows users to better understand why this signature is
present in the log, and to be able to better focus malware analysis.

Two helpers have been included to specify matching data.

.. function:: Signature.add_match(process, type, match)

    Adds a match to the signature. Can be called several times for the same signature.

    :param process: process dictionary (same as the ``on_call`` argument). Should be ``None`` except when used in evented signatures.
    :type process: dict
    :param type: nature of the matching data. Can be anything (ex: ``'file'``, ``'registry'``, etc.). If match is composed of api calls (when used in evented signatures), should be ``'api'``.
    :type type: string
    :param match: matching data. Can be a single element or a list of elements. An element can be a string, a dict or an API call (when used in evented signatures).

    Example Usage, with a single element:

    .. code-block:: python
        :linenos:

        self.add_match(None, "url", "http://malicious_url_detected.com")

    Example Usage, with a more complex signature, needing several API calls to be triggered:

    .. code-block:: python
        :linenos:

        self.signs = []
        self.signs.append(first_api_call)
        self.signs.append(second_api_call)
        self.add_match(process, 'api', self.signs)

.. function:: Signature.has_matches()

    Checks whether the current signature has any matching data registered. Returns ``True`` in case it does, otherwise returns ``False``.

    This can be used to easily add several matches for the same signature. If you want to do so, make sure that all the api calls are scanned by making sure that ``on_call`` never returns ``True``. Then, use ``on_complete`` with ``has_matches`` so that the signature is triggered if any match was previously added.

    :rtype: boolean

    Example Usage, from the `network_tor` signature:

    .. code-block:: python
        :linenos:

        def on_call(self, call, process):
            if self.check_argument_call(call,
                                        pattern="Tor Win32 Service",
                                        api="CreateServiceA",
                                        category="services"):
                self.add_match(process, "api", call)

        def on_complete(self):
            return self.has_matches()

.. _Helpers:

Helpers
=======

As anticipated, from version 0.5 the ``Signature`` base class also provides
some helper methods that simplify the creation of signatures and avoid the need
for you having to access the global container directly (at least most of the times).

Following is a list of available methods.

.. function:: Signature.check_file(pattern[, regex=False])

    Checks whether the malware opened or created a file matching the specified pattern. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: file name or file path pattern to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_file(pattern=".*\.exe$", regex=True)

.. function:: Signature.check_key(pattern[, regex=False])

    Checks whether the malware opened or created a registry key matching the specified pattern. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: registry key pattern to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_key(pattern=".*CurrentVersion\\Run$", regex=True)

.. function:: Signature.check_mutex(pattern[, regex=False])

    Checks whether the malware opened or created a mutex matching the specified pattern. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: mutex pattern to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_mutex("mutex_name")

.. function:: Signature.check_api(pattern[, process=None[, regex=False]])

    Checks whether Windows function was invoked. Returns ``True`` in case it was, otherwise returns ``False``.

    :param pattern: function name pattern to be matched
    :type pattern: string
    :param process: name of the process performing the call
    :type process: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_api(pattern="URLDownloadToFileW", process="AcroRd32.exe")

.. function:: Signature.check_argument(pattern[, name=Name[, api=None[, category=None[, process=None[, regex=False]]]])

    Checks whether the malware invoked a function with a specific argument value. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: argument value pattern to be matched
    :type pattern: string
    :param name: name of the argument to be matched
    :type name: string
    :param api: name of the Windows function associated with the argument value
    :type api: string
    :param category: name of the category of the function to be matched
    :type category: string
    :param process: name of the process performing the associated call
    :type process: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_argument(pattern=".*CAPE.*", category="filesystem", regex=True)

.. function:: Signature.check_ip(pattern[, regex=False])

    Checks whether the malware contacted the specified IP address. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: IP address to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_ip("123.123.123.123")

.. function:: Signature.check_domain(pattern[, regex=False])

    Checks whether the malware contacted the specified domain. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: domain name to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_domain(pattern=".*capesandbox.com$", regex=True)

.. function:: Signature.check_url(pattern[, regex=False])

    Checks whether the malware performed an HTTP request to the specified URL. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: URL pattern to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_url(pattern="^.+\/load\.php\?file=[0-9a-zA-Z]+$", regex=True)

.. _Categories:

Categories
==========
You can put signatures into categories to facilitate grouping or sorting. You can create your own category if you wish, but
it is easier for other users if you associate a signature
with a category that already exists. Here is a list of all categories available:

- `account`: Adds or manipulates an administrative user account.
- `anti-analysis`: Constructed to conceal or obfuscate itself to prevent analysis.
- `anti-av`: Attempts to conceal itself from detection by antivirus.
- `anti-debug`: Attempts to detect if it is being debugged.
- `anti-emulation`: Detects the presence of an emulator.
- `anti-sandbox`: Attempts to detect if it is in a sandbox.
- `anti-vm`: Attempts to detect if it is being run in virtualized environment.
- `antivirus`: Antivirus hit. File is infected.
- `banker`: Designed to gain access to confidential information stored or processed through online banking.
- `bootkit`: Manipulates machine configurations that would affect the boot of the machine.
- `bot`: Appears to be a bot or exhibits bot-like behaviour.
- `browser`: Manipulates browser-settings in a suspicious way.
- `bypass`: Attempts to bypass operating systems security controls (firewall, amsi, applocker, UAC, etc.)
- `c2`: Communicates with a server controlled by a malicious actor.
- `clickfraud`: Manipulates browser settings to allow for insecure clicking.
- `command`: A suspicious command was observed.
- `credential_access`: Uses techniques to access credentials.
- `credential_dumping`: Uses techniques to dump credentials.
- `cryptomining`: Facilitates mining of cryptocurrency.
- `discovery`: Uses techniques for discovery information about the system, the user, or the environment.
- `dns`: Uses suspicious DNS queries.
- `dotnet`: .NET code is used in a suspicious manner.
- `downloader`: Trojan that downloads installs files.
- `dropper`: Trojan that drops additional malware on an affected system.
- `encryption`: Encryption algorithms are used for obfuscating data.
- `evasion`: Techniques are used to avoid detection.
- `execution`: Uses techniques to execute harmful code or create executables that could run harmful code.
- `exploit`: Exploits an known software vulnerability or security flaw.
- `exploit_kit`: Programs designed to crack or break computer and network security measures.
- `generic`: Basic operating system objects are used in suspicious ways.
- `infostealer`: Collects and disseminates information such as login details, usernames, passwords, etc.
- `injection`: Input is not properly validated and gets processed by an interpreter as part of a command or query.
- `keylogger`: Monitoring software detected.
- `lateral`: Techniques used to move through environment and maintain access.
- `loader`: Download and execute additional payloads on compromised machines.
- `locker`: Prevents access to system data and files.
- `macro`: A set of commands that automates a software to perform a certain action, found in Office macros.
- `malware`: The file uses techniques associated with malicious software.
- `martians`: Command shell or script process was created by unexpected parent process.
- `masquerading`: The name or location of an object is manipulated to evade defenses and observation.
- `network`: Suspicious network traffic was observed.
- `office`: Makes API calls not consistent with expected/standard behaviour.
- `packer`: Compresses, encrypts, and/or modifies a malicious file's format.
- `persistence`: Technique used to maintain presence in system(s) across interruptions that could cut off access.
- `phishing`: Techniques were observed that attempted to obtain information from the user.
- `ransomware`: Designed to block access to a system until a sum of money is paid.
- `rat`: Designed to provide the capability of covert surveillance and/or unauthorized access to a target.
- `rootkit`: Designed to provide continued privileged access to a system while actively hiding its presence.
- `static`: A suspicious characteristic was discovered during static analysis.
- `stealth`: Leverages/modifies internal processes and settings to conceal itself.
- `trojan`: Presents itself as legitimate in attempt to infiltrate a system.
- `virus`: Malicious software program.

Troubleshooting
===============
No signatures
-------------

Whenever you submit a sample for analysis, when it finishes you should be able to inspect the identified signatures. If you see the *No signatures* message, you might need to download or update them. Example from the web interface:

    .. image:: ../_images/screenshots/no_signatures.png
        :align: center


If no signatures are showing when executing a given report, you must use the ``utils/community.py`` tool so as to download them:: 

$ sudo -u cape poetry run python3 utils/community.py -waf

If the execution of the script does not end successfully, make sure you solve it. For example::

    Installing REPORTING
    File "/opt/CAPEv2/modules/reporting/__init__.py" installed
    File "/opt/CAPEv2/modules/reporting/elasticsearchdb.py" installed
    Traceback (most recent call last):
      File "/opt/CAPEv2/utils/community.py", line 257, in <module>
        main()
      File "/opt/CAPEv2/utils/community.py", line 252, in main
        install(enabled, args.force, args.rewrite, args.file, args.token)
      File "/opt/CAPEv2/utils/community.py", line 180, in install
        open(filepath, "wb").write(t.extractfile(member).read())
    PermissionError: [Errno 13] Permission denied: '/opt/CAPEv2/modules/reporting/elasticsearchdb.py'

happened because ``elasticsearchdb.py`` did not belong to `cape:cape` but to `root:root`.

After *chowning* it to `cape:cape`, the script finished successfully. You should now see in the report page something similar to this: 

    .. image:: ../_images/screenshots/signatures.png
        :align: center

Errors/warnings in the logs
---------------------------

If you ever face errors or warnings in the logs related to the signatures module (like `Signature spawns_dev_util crashing after update <https://github.com/kevoreilly/CAPEv2/issues/1261>`_)), chances are high you must update the signatures you are working with. To do so, just run the ``community``` utility like so::

$ sudo -u cape poetry run python3 community.py -waf -cr


