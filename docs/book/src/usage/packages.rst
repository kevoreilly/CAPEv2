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

    * ``access``: used to run and analyze **Microsoft Office Access files** via ``msaccess.exe``.
    * ``applet``: used to run and analyze **Java applets** via ``firefox.exe`` or ``iexplore.exe``.

        **Options**:
            * ``class``: specify the name of the class to be executed. This option is mandatory for correct execution.

    * ``archive``: used to run and analyze **archives such as ISO, VHD and anything else that 7-Zip can extract** via ``7z.exe``.

        Explanation how it works can be found in this `Technical Session for CyberShock 2022, presented by CCCS <https://youtu.be/-70Mlkmtdds?t=13013>`_.

        *NB*: Passing ``file=`` as a task option will ensure that the entire archive is passed to the victim VM and extracted there,
        prior to executing files of interest within in the extracted folder.

        **Options**:
            * ``arguments``: specify arguments to pass to the DLL through commandline.
            * ``dllloader``: specify a process name to use to fake the DLL launcher name instead of ``rundll32.exe`` (this is used to fool possible anti-sandboxing tricks of certain malware).
            * ``file``: specify the name of the file contained in the archive to execute. If none is specified, CAPE will try to execute *sample.exe*.
            * ``function``: specify the function to be executed. If none is specified, CAPE will try to run the entry at ordinal 1.
            * ``password``: specify the password of the archive. If none is specified, CAPE will try to extract the archive without password or use the password "*infected*".

    * ``chm``: used to run and analyze **Microsoft Compiled HTML Help files** via ``hh.exe``.
    * ``chrome``: used to open **the given URL** via ``chrome.exe``.
    * ``chromium``: used to open **the given URL** via the Chromium version of ``chrome.exe``.
    * ``cpl``: used to run and analyze **Control Panel Applets** via ``control.exe``.
    * ``dll``: used to run and analyze **Dynamically Linked Libraries** via ``rundll32.exe``.

        **Options**:
            * ``arguments``: specify arguments to pass to the DLL through commandline.
            * ``dllloader``: specify a process name to use to fake the DLL launcher name instead of ``rundll32.exe`` (this is used to fool possible anti-sandboxing tricks of certain malware).
            * ``enable_mutli``: *[yes/no, true/false, on/off]*: if enabled, multiple functions can be run.
            * ``function``: specify the function to be executed. If none is specified, CAPE will try to run all available functions,
              up to the limit found in the `max_dll_exports` task option.
            * ``max_dll_exports``: A positive integer, representing how many functions you wish to execute. `enable_mutli` must be enabled.
            * ``use_export_name``: *[yes/no, true/false, on/off]*: if enabled, functions will be run by name rather than by ordinal number.

    * ``doc_antivm``: used to run and analyze **Microsoft Word documents** via ``winword.exe`` or ``wordview.exe``.

        *NB*: Multiple applications are executed prior to the sample's execution, to prevent certain anti-vm techniques.

        **Options**:
            * ``free``: *[yes/no]* if enabled, no behavioral logs will be produced and the malware will be executed freely.

    * ``doc``: used to run and analyze **Microsoft Word documents** via ``winword.exe``.

    * ``doc2016``: used to run and analyze **Microsoft Word documents** via Microsoft Office 2016's ``winword.exe``.
    * ``edge``: used to open **the given URL** via ``msedge.exe``.
    * ``eml``: used to run and analyze **Electronic Mail files** via ``outlook.exe``.
    * ``exe``: default analysis package used to run and analyze generic **Windows executables**.

        **Options**:
            * ``appdata``: *[yes/no]* if enabled, run the executable from the APPDATA directory.
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
            * ``runasx86``: *[yes/no]* if enabled, run ``CorFlags.exe`` with ``/32bit+`` prior to execution.

    * ``firefox``: used to open **the given URL** via ``firefox.exe``.
    * ``generic``: used to run and analyze **generic samples** via ``cmd.exe``.
    * ``hta``: used to run and analyze **HTML Applications** via ``mshta.exe``.
    * ``hwp``: used to run and analyze **Hangul Word Processor files** via ``hwp.exe`` or ``hword.exe``.
    * ``ichitaro``: used to run and analyze **Ichitaro Word Processor files** via ``taroview.exe``.
    * ``ie``: used to open **the given URL** via ``iexplore.exe``.
    * ``inp``: used to run and analyze **Inpage Word Processor files** via ``inpage.exe``.
    * ``jar``: used to run and analyze **Java JAR containers** via ``java.exe``.

        **Options**:
            * ``class``: specify the path of the class to be executed. If none is specified, CAPE will try to execute the main function specified in the Jar's MANIFEST file.

    * ``js_antivm``: used to run and analyze **JavaScript and JScript Encoded files** via ``wscript.exe``.

        *NB*: This package opens 20 Calculator windows prior to execution, to prevent certain anti-vm techniques.

        **Options**:
            * ``free``: *[yes/no]* if enabled, no behavioral logs will be produced and the malware will be executed freely.

    * ``js``: used to run and analyze **JavaScript and JScript Encoded files** via ``wscript.exe``.

        *NB*: This package opens 20 Calculator windows prior to .jse execution, to prevent certain anti-vm techniques.

        **Options**:
            * ``free``: *[yes/no]* if enabled, no behavioral logs will be produced and the malware will be executed freely.

    * ``lnk``: used to run and analyze **Windows Shortcuts** via ``cmd.exe``.
    * ``mht``: used to run and analyze **MIME HTML files** via ``iexplore.exe``.
    * ``msbuild``: used to run and analyze **Microsoft Build Engine files** via ``msbuild.exe``.
    * ``msg``: used to run and analyze **Outlook Message Item files** via ``outlook.exe``.
    * ``msi``: used to run and analyze **Windows Installer Package files** via ``msiexec.exe``.
    * ``nsis``: used to run and analyze **Nullsoft Scriptable Install System files** via ``cmd.exe``.
    * ``ollydbg``: used to run and analyze **generic samples** via ``ollydbg.exe``.

        *NB*: The ``ollydbg.exe`` application must be in the analyzer's ``bin`` directory.

        **Options**:
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.

    * ``one``: used to run and analyze **Microsoft OneNote documents** via ``onenote.exe``.
    * ``pdf``: used to run and analyze **PDF documents** via ``acrord32.exe``.
    * ``ppt``: used to run and analyze **Microsoft PowerPoint documents** via ``powerpnt.exe``.
    * ``ppt2016``: used to run and analyze **Microsoft PowerPoint documents** via Microsoft Office 2016's ``powerpnt.exe``.
    * ``ps1_x64``: used to run and analyze **PowerShell scripts** via ``powershell.exe`` in SysNative.

        *NB*: This package uses the ``powershell.exe`` in SysNative.

    * ``ps1``: used to run and analyze **PowerShell scripts** via ``powershell.exe`` in System32.

        *NB*: This package uses the ``powershell.exe`` in System32.

    * ``pub``: used to run and analyze **Microsoft Publisher documents** via ``mspub.exe``.
    * ``pub2016``: used to run and analyze **Microsoft Publisher documents** via Microsoft Office 2016's ``mspub.exe``.
    * ``python``: used to run and analyze **Python scripts** via ``py.exe`` or ``python.exe``.

        **Options**:
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.

    * ``rar``: extracts **WinRAR Compressed Archive files** via the rarfile Python package, and runs an executable file (if it exists), with ``cmd.exe``.

        *NB*: The rarfile Python package must be installed on the guest.

        **Options**:
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
            * ``file``: specify the name of the file contained in the archive to execute. If none is specified, CAPE will try to execute *sample.exe*.
            * ``password``: specify the password of the archive. If none is specified, CAPE will try to extract the archive without password or use the password "*infected*".

    * ``reg``: used to run and analyze **Registry files** via ``reg.exe``.
    * ``regsvr``: used to run and analyze **Dynamically Linked Libraries** via ``regsvr32.exe``.

        **Options**:
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.

    * ``sct``: used to run and analyze **Windows Scriptlet files** via ``regsvr32.exe``.
    * ``service_dll``: used to run and analyze **Service Dynamically Linked Libraries** via ``sc.exe``.

        **Options**:
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
            * ``servicename``: specify the name of the service. If no name is provided, CAPE with default to using *CAPEService*.
            * ``servicedesc``: specify the description of the service. If no name is provided, CAPE with default to using *CAPE Service*.

    * ``service``: used to run and analyze **Services** via ``sc.exe``.

        **Options**:
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
            * ``servicename``: specify the name of the service. If no name is provided, CAPE with default to using *CAPEService*.
            * ``servicedesc``: specify the description of the service. If no name is provided, CAPE with default to using *CAPE Service*.

    * ``shellcode_x64``: used to run and analyze **Shellcode** via the 64-bit CAPE loader.

        **Options**:
            * ``offset``: specify the offset to run with the 64-bit CAPE loader.

    * ``shellcode``: used to run and analyze **Shellcode** via the 32-bit CAPE loader, with unpacking!

        **Options**:
            * ``offset``: specify the offset to run with the 32-bit CAPE loader.

    * ``swf``: used to run and analyze **Shockwave Flash** via ``flashplayer.exe``.

        *NB*: You need to have ``flashplayer.exe`` in the analyzer's ``bin`` folder.

    * ``vbejse``: used to run and analyze **VBScript Encoded and JScript Encoded files** via ``wscript.exe``.
    * ``vbs``: used to run and analyze **VBScript and VBScript Encoded files** via ``wscript.exe``.
    * ``wsf``: used to run and analyze **Windows Script Files** via ``wscript.exe``.
    * ``xls``: used to run and analyze **Microsoft Excel documents** via ``excel.exe``.
    * ``xls2016``: used to run and analyze **Microsoft Excel documents** via Microsoft Office 2016's ``excel.exe``.
    * ``xslt``: used to run and analyze **eXtensible Stylesheet Language Transformation Files** via ``wmic.exe``.
    * ``xps``: used to run and analyze **XML Paper Specification Files** via ``xpsrchvw.exe``.
    * ``zip_compound``: used to run and analyze **Zip archives** with more specific settings.

        *NB*: Either ``file`` option must be set, or a ``__configuration.json`` file must be present in the zip file.
        Sample json file:

        .. code-block:: json

            {
                "path_to_extract": {
                    "a.exe": "%USERPROFILE%\\Desktop\\a\\b\\c",
                    "folder_b": "%appdata%"
                },
                "target_file":"a.exe"
            }

        **Options**:
            * ``appdata``: *[yes/no]* if enabled, create custom folders in the APPDATA directory.
            * ``arguments``: specify arguments to pass to the DLL through commandline.
            * ``curdir``: specify the directory to create custom folders.
            * ``dllloader``: specify a process name to use to fake the DLL launcher name instead of ``rundll32.exe`` (this is used to fool possible anti-sandboxing tricks of certain malware).
            * ``file``: specify the name of the file contained in the archive to execute. If none is specified, a ``__configuration.json`` file must be present in the zip file.
            * ``function``: specify the function to be executed. If none is specified, CAPE will try to run the entry at ordinal 1.
            * ``password``: specify the password of the archive. If none is specified, CAPE will try to extract the archive without password or use the password "*infected*".

    * ``zip``: extract **Zip archives** via the zipfile Python package, and runs an executable file (if it exists), with ``cmd.exe``.

        **Options**:
            * ``appdata``: *[yes/no]* if enabled, create custom folders in the APPDATA directory.
            * ``arguments``: specify arguments to pass to the DLL through commandline.
            * ``dllloader``: specify a process name to use to fake the DLL launcher name instead of ``rundll32.exe`` (this is used to fool possible anti-sandboxing tricks of certain malware).
            * ``file``: specify the name of the file contained in the archive to execute. If none is specified, CAPE will try to execute *sample.exe*.
            * ``function``: specify the function to be executed. If none is specified, CAPE will try to run the entry at ordinal 1.
            * ``password``: specify the password of the archive. If none is specified, CAPE will try to extract the archive without password or use the password "*infected*".

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
