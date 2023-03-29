# Add uppercase version too as ComputerName is USERNAME-PC
SANDBOX_USERNAMES = []

# Files blacklisted because of generating noise in reports.
FILES_DENYLIST = [
    "PIPE\\srvsvc",
    "Device\\KsecDD",
    "MountPointManager",
    "DosDevices\\pipe",
    "\\Device\\RasAcd",
    "system32\\WindowsPowerShell\\v1.0\\Modules",  # Powershell path.
    "WindowsPowerShell\\Modules",
    "Windows\\Microsoft.Net\\assembly",
    "\\??\\Nsi",
]

FILES_ENDING_DENYLIST = (".mui", "Zone.Identifier", ".Local", ".Local\\")

SERVICES_DENYLIST = ["RASMAN", "WinHttpAutoProxySvc", "gpsvc", "CryptSvc"]
MUTEX_DENYLIST = []

NORMALIZED_PATHS = {
    "C:\\Windows": "%WINDIR%",
    "C:\\Users\\<USER>\\AppData\\Local": "%LocalAppData%",
    "C:\\Users\\<USER>\\AppData\\": "%APPDATA%",
}

REGISTRY_TRANSLATION = {
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKEY_CURRENT_USER": "HKCU",
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_USERS": "HKU",
    "HKEY_CURRENT_CONFIG": "HKCC",
    "\\Registry\\User": "HKCU",
    "\\Registry\\Machine": "HKLM",
}
