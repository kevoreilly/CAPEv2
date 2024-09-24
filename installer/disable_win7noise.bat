REM NTP
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v LocalNTP /t REG_DWORD /d 0 /f
REM HELP
REM http://www.windows-commandline.com/start-stop-service-command-line/
REM disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
REM disable Windows defender
sc config WinDefend start= disabled
REM disable windows update
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 1 /f
REM disable aero
net stop uxsms
REM disable the firewall
netsh advfirewall set allprofiles state off
REM disable IPv6
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled
REM disable active probing
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v EnableActiveProbing /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v EnableActiveProbing /t REG_DWORD /d 0 /f
REM disable passive probing
reg add  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v PassivePollPeriod /t REG_DWORD /d 0 /f
REM disable SSDP
sc config SSDPSRV start= disabled
net stop SSDPSRV
REM disable computer browsing
sc stop Browser
sc config Browser start= disabled
REM disable WinHTTP Web Proxy Auto-Discovery
reg add "HKLM\SYSTEM\CurrentControlSet\services\WinHttpAutoProxySvc" /v Start /t REG_DWORD /d 4 /f
REM disable Function Discovery Resource Publication service
reg add "HKLM\SYSTEM\CurrentControlSet\services\FDResPup" /v Start /t REG_DWORD /d 4 /f
REM IE blank page
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /V "Start Page" /D "" /F
REM disable IExplorer Proxy
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t  REG_DWORD /d 00000000 /f
REM disable netbios in TCP/IP
wmic nicconfig where index=8 call SetTcpipNetbios 2
REM disable netbios service
reg add "HKLM\SYSTEM\CurrentControlSet\services\Lmhosts" /v Start /t REG_DWORD /d 4 /f
REM disable LLMNR
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f
REMdisable SQM
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FlexGo\FGNotify\Prechecks"  /v Sqm /t REG_DWORD /d 00000002 /f
REM Disable cert check
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo" /v DefaultSslCertCheckMode /t REG_DWORD /d 1 /f
REM disable ClickToRunSvc
sc stop "ClickToRunSvc"
sc config "ClickToRunSvc" start= disabled
REM disable monitor-timeout
POWERCFG -CHANGE -monitor-timeout-ac 0
POWERCFG -CHANGE -monitor-timeout-dc 0

REM dr.watson
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v AUTO /t REG_SZ /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /v AutoExclusionList /t REG_SZ /d 0 /f

REM curtain
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f /reg:64
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 00000001 /f /reg:64
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 00000001 /f /reg:64
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d C:\PSTranscipts /f /reg:64
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 00000001 /f /reg:64

REM disable windows defender
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f

REM https://superuser.com/questions/972501/how-to-stop-microsoft-from-gathering-telemetry-data-from-windows-7-8-and-8-1
sc stop DiagTrack
sc stop dmwappushservice
sc delete DiagTrack
sc delete dmwappushservice
echo "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\WMI\AutoLogger" /v AutoLogger-Diagtrack-Listener /t DWORD /d 0 /f

REM Win10/11 telemetry
sc config DiagTrack start= disabled
sc config dmwappushservice start= disabled

REM schtasks
schtasks.exe /Change /TN "\Microsoft\Office\Office Automatic Updates 2.0" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Office\Office ClickToRun Service Monitor" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Office\Office Feature Updates" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Office\Office Feature Updates Logon" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Disable /ru ""

schtasks.exe /Change /TN "\Microsoft\Windows\Application Experience\AitAgent" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Application Experience\ProgramData\Updater" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable /ru ""

schtasks.exe /Change /TN "\CCleaner Update" /Disable /ru ""
schtasks.exe /Change /TN "\CCleaner UpdateSkipUAC" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable /ru ""
schtasks.exe /Change /TN "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable /ru ""


REM Uninstall telemetry updates
wusa /uninstall /kb:3065988 /quiet /norestart
wusa /uninstall /kb:3083325 /quiet /norestart
wusa /uninstall /kb:3083324 /quiet /norestart
wusa /uninstall /kb:2976978 /quiet /norestart
wusa /uninstall /kb:3075853 /quiet /norestart
wusa /uninstall /kb:3065987 /quiet /norestart
wusa /uninstall /kb:3050265 /quiet /norestart
wusa /uninstall /kb:3050267 /quiet /norestart
wusa /uninstall /kb:3075851 /quiet /norestart
wusa /uninstall /kb:2902907 /quiet /norestart
wusa /uninstall /kb:3068708 /quiet /norestart
wusa /uninstall /kb:3022345 /quiet /norestart
wusa /uninstall /kb:2952664 /quiet /norestart
wusa /uninstall /kb:2990214 /quiet /norestart
wusa /uninstall /kb:3035583 /quiet /norestart
wusa /uninstall /kb:971033 /quiet /norestart
wusa /uninstall /kb:3021917 /quiet /norestart
wusa /uninstall /kb:3044374 /quiet /norestart
wusa /uninstall /kb:3046480 /quiet /norestart
wusa /uninstall /kb:3075249 /quiet /norestart
wusa /uninstall /kb:3080149 /quiet /norestart
wusa /uninstall /kb:2977759 /quiet /norestart
wusa /uninstall /kb:3083710 /quiet /norestart
wusa /uninstall /kb:3083711 /quiet /norestart
wusa /uninstall /kb:3112336 /quiet /norestart
wusa /uninstall /kb:3123862 /quiet /norestart

REM office 2010
reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\Common\Security" /v DisableAllActiveX /t  REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\Common\Security" /v UFIControls /t  REG_DWORD /d 1 /f
for %%x in (Word Excel PowerPoint Publisher Outlook) do (
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Common\General" /v ShownOptIn /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security" /v VBAWarnings /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security" /v AccessVBOM /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security" /v DisableDDEServerLaunch /t  REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security" /v ExtensionHardening /t  REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security" /v ShownOptIn /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security" /v ShownOptIn /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security" /v ShownOptIn /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\14.0\%%x\Security" /v MarkInternalAsUnsafe /t  REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security\ProtectedView" /v DisableAttachmentsInPV /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security\ProtectedView" /v DisableInternetFilesInPV /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security\ProtectedView" /v DisableUnsafeLocationsInPV /t  REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\%%x\Security" /v EnableDEP /t  REG_DWORD /d 1 /f
)
