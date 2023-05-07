rem Chocolatey now requires PowerShell v3 (or higher) and .NET 4.0 (or higher) due to recent upgrades to TLS 1.2. 
rem Please ensure .NET 4+ and PowerShell v3+ are installed prior to attempting FLARE VM installation. 
rem Below are links to download .NET 4.5 and WMF 5.1 (PowerShell 5.1).
rem .NET 4.5 https://www.microsoft.com/en-us/download/details.aspx?id=30653
rem WMF 5.1 https://www.microsoft.com/en-us/download/details.aspx?id=54616


powershell -Command "if ($PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.PSVersion.Minor -ge 1 ){Set-ExecutionPolicy Bypass -Scope Process -Force; iwr https://community.chocolatey.org/install.ps1 -UseBasicParsing | iex } else {Write-Output "'Chocolatey now requires PowerShell v3 (or higher) and .NET 4.0 (or higher) due to recent upgrades to TLS 1.2. Please ensure .NET 4+ and PowerShell v3+ are installed prior to attempting FLARE VM installation. `nBelow are links to download .NET 4.5 and WMF 5.1 (PowerShell 5.1). .NET 4.5 https://www.microsoft.com/en-us/download/details.aspx?id=30653 WMF 5.1 https://www.microsoft.com/en-us/download/details.aspx?id=54616'"}"
choco upgrade chocolatey
choco install -y dotnetfx dotnet4.7.2 dotnet vcredist-all wixtoolset msxml4.sp3 msxml6.sp1

pip3 install pillow pywintrace
