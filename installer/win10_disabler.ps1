# there is way much better tools for this, but some of them doesn't do what we need

# https://github.com/ntdevlabs/tiny11builder

# see the Microsoft Defender Antivirus status and press
# Get-MpComputerStatus

# List preferences
# Get-MpPreference

# https://github.com/W4RH4WK/Debloat-Windows-10/tree/master

Write-Output "Disabling Windows defender features..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
Set-MpPreference DisableAntiSpyware $true -ExclusionPath C:\ -DisableRemovableDriveScanning $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true  -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
# https://www.alitajran.com/disable-windows-firewall-with-powershell/

Write-Output "Disabling Firewall..."
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False


# https://stackoverflow.com/a/68843405
Write-Output "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0

# Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'Security_HKLM_only'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'Security_HKLM_only' -Value 0 -PropertyType 'DWord'
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'Zones'
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones' -Name '2'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2' -Name '2301' -Value 3 -PropertyType 'DWord'


# https://superuser.com/a/1767126
Write-Host "Disabling browser auto update..."

$msEdgeInstallationPath = 'C:\Program Files (x86)\Microsoft'
$Process2Monitor = "MicrosoftEdgeUpdate";
For ($i = 0; $i -lt 5; $i++) {
    $ProcessesFound = Get-Process | ? { $Process2Monitor -contains $_.Name } | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Microsoft Edge updater running... Killing it" | Write-Host; Stop-Process -Name $Process2Monitor -Force; Break } else { "Microsoft Edge updater not running. Retrying in 1 second..." | Write-Host; Start-Sleep -Seconds 1}
}

Write-Host "Waiting for Microsoft Edge update to finish (60s Timeout)"
For ($i = 0; $i -lt 60; $i++) {
    $ProcessesFound = Get-Process | ? { $Process2Monitor -contains $_.Name } | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Microsoft Edge updater running... waiting its finish..." | Write-Host; Start-Sleep -Seconds 1 } else { "Microsoft Edge updater finished." | Write-Host; Break}
}
Rename-Item -Path "$msEdgeInstallationPath\EdgeUpdate\MicrosoftEdgeUpdate.exe" -NewName MicrosoftEdgeUpdateDisabled.exe -Force

Write-Output "Disabling telemetry via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

Write-Host "Block scheduled telemetry tasks"
# See reference: https://answers.microsoft.com/en-us/windows/forum/windows_10-performance/permanently-disabling-windows-compatibility/6bf71583-81b0-4a74-ae2e-8fd73305aad1
$tasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Application Experience\StartupAppTask"
    "\Microsoft\Windows\Application Experience\PcaPatchDbTask"
)

foreach ($task in $tasks) {
   Disable-ScheduledTask -TaskName $task
}

<#
# CAPE agent.py autoinstall
$jobname = "Recurring PowerShell Task"
$script =  "w32tm /resync"
$action = New-ScheduledTaskAction -Execute "$pshome\powershell.exe" -Argument  "$script"
$duration = ([timeSpan]::maxvalue)
$repeat = (New-TimeSpan -hours 3)
$trigger =New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration


$msg = "Enter the username and password that will run the task";
$credential = $Host.UI.PromptForCredential("Task username and password",$msg,"$env:userdomain\$env:username",$env:userdomain)
$username = $credential.UserName
$password = $credential.GetNetworkCredential().Password
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
 Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -RunLevel Highest -User $username -Password $password -Settings $settings
#>

Write-Output "Remove WindowsApp to prevent MS StoreStartup"
Remove-Item -path C:\Users\Default\AppData\Local\Microsoft\WindowsApp -recurse
