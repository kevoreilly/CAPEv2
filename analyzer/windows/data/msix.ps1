<#
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

https://github.com/Microsoft/Terminal#installing-and-running-windows-terminal
NOTE: If you are using PowerShell 7+, please run
Import-Module Appx -UseWindowsPowerShell
before using Add-AppxPackage.
Add-AppxPackage Microsoft.WindowsTerminal_<versionNumber>.msixbundle

-NoProfile -ExecutionPolicy bypass

$ps_version=(Get-host).version.Major
$ps_7_command = ""
if ($ps_version -gt 5)
{
    $ps_7_command = "Import-Module Appx -UseWindowsPowerShell"
}

# Microsoft Windows 10 X
$os=Get-ComputerInfo | Select-Object OSName| ForEach-Object {$_.OsName }

https://learn.microsoft.com/en-us/windows/msix/package/unsigned-package
-AllowUnsigned only available on Window 11#>

$pre_last_installed_app=Get-StartApps | Select-Object AppID -last 1 | ForEach-Object {$_.AppID }
Add-AppPackage -path $Args[0]
$last_installed_app=Get-StartApps | Select-Object AppID -last 1 | ForEach-Object {$_.AppID }

if ($pre_last_installed_app -eq $last_installed_app)
{
    Write-Host Script Start
    Write-Host "MSIX package wasn't installed properly, see screenshots and logs for more details"
    exit
    Write-Host Script End
}
# explorer shell:AppsFolder\$last_installed_app
Start-Process shell:AppsFolder\$last_installed_app
# -Verb RunAs
