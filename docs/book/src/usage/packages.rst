=================
Analysis Packages
=================

The **analysis packages** are a core component of CAPE Sandbox.
They consist of structured Python classes that, when executed in the guest machines,
describe how CAPE's analyzer component should conduct the analysis.

CAPE provides some default analysis packages that you can use, but you can
create your own or modify the existing ones.
You can find them at *analyzer/windows/modules/packages/*.

As described in :doc:`../usage/submit`, you can specify some options to the
analysis packages in the form of ``key1=value1,key2=value2``. The existing analysis
packages already include some default options that can be enabled.

The following is a list of the existing packages in alphabetical order:

    .. warning:: PROBABLY outdated, see  code for more details

    * ``applet``: used to analyze **Java applets**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``class``: specify the name of the class to be executed. This option is mandatory for correct execution.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``bin``: used to analyze generic binary data, such as **shellcodes**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``cpl``: used to analyze **Control Panel Applets**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``dll``: used to run and analyze **Dynamically Linked Libraries**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``function``: specify the function to be executed. If none is specified, CAPE will try to run ``DllMain``.
            * ``arguments``: specify arguments to pass to the DLL through commandline.
            * ``dllloader``: specify a process name to use to fake the DLL launcher name instead of rundll32.exe (this is used to fool possible anti-sandboxing tricks of certain malware)
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``doc``: used to run and analyze **Microsoft Word documents**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``exe``: default analysis package used to analyze generic **Windows executables**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``generic``: used to run and analyze **generic samples** via cmd.exe.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``html``: used to analyze **Internet Explorer**'s behavior when opening the given HTML file.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``ie``: used to analyze **Internet Explorer**'s behavior when opening the given URL.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``jar``: used to analyze **Java JAR** containers.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``class``: specify the path of the class to be executed. If none is specified, Cuckoo will try to execute the main function specified in the Jar's MANIFEST file.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``msi``: used to run and analyze **MSI windows installer**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``pdf``: used to run and analyze **PDF documents**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``ppt``: used to run and analyze **Microsoft PowerPoint documents**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``ps1``: used to run and analyze **PowerShell scripts**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``python``: used to run and analyze **Python scripts**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``vbs``: used to run and analyze **VBScript files**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``xls``: used to run and analyze **Microsoft Excel documents**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``zip``: used to run and analyze **Zip archives**.

        **Options**:
            * ``file``: specify the name of the file contained in the archive to execute. If none is specified, CAPE will try to execute *sample.exe*.
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
            * ``password``: specify the password of the archive. If none is specified, CAPE will try to extract the archive without password or use the password "*infected*".
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for capemon.dll.

    * ``zip_compound``: used to run and analyze **Zip archives** with more specific settings.

        **Options**:
            * Similar settings as ``zip`` package
            * Either ``file`` option must be set, or a __configuration.json file must be present in the zip file.
            * Sample json file:

    .. code-block:: json

        {
            "path_to_extract": {
                "a.exe": "%USERPROFILE%\\Desktop\\a\\b\\c",
                "folder_b": "%appdata%"
            },
            "target_file":"a.exe"
        }

You can find more details on how to start creating analysis packages in the
:doc:`../customization/packages` customization chapter.

As you already know, you can select which analysis package to use by specifying
its name at submission time (see :doc:`submit`) as follows::

    $ ./utils/submit.py --package <package name> /path/to/malware

If no package is specified, CAPE will try to detect the file type and select
the correct analysis package accordingly. If the file type is not supported by
default, the analysis will be aborted. Therefore we encourage to
specify the package name whenever possible.

For example, to launch a malware sample and specify some options you can do::

    $ ./utils/submit.py --package dll --options function=FunctionName,loader=explorer.exe /path/to/malware.dll
