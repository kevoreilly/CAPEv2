=======
Curtain
=======

* Detailed writeup by `Mandiant's powershell blogpost`_
* Configuration required in Virtual Machine. Example for Windows 7::

    Windows 7 SP1, .NET at least 4.5, powershell 5 preferly over v4
    KB3109118 - Script block logging back port update for WMF4
    x64 - https://cuckoo.sh/vmcloak/Windows6.1-KB3109118-v4-x64.msu
    x32 - https://cuckoo.sh/vmcloak/Windows6.1-KB3109118-v4-x86.msu
    KB2819745 - WMF 4 (Windows Management Framework version 4) update for Windows 7

    x64 - https://cuckoo.sh/vmcloak/Windows6.1-KB2819745-x64-MultiPkg.msu
    x32 - https://cuckoo.sh/vmcloak/Windows6.1-KB2819745-x86-MultiPkg.msu
    KB3191566 - https://www.microsoft.com/en-us/download/details.aspx?id=54616

    You should create following registry entries
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f /reg:64
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 00000001 /f /reg:64
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 00000001 /f /reg:64
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d C:\PSTranscipts /f /reg:64
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 00000001 /f /reg:64


.. _`Mandiant's powershell blogpost`: https://www.mandiant.com/resources/blog/greater-visibility
