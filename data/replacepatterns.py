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
    "Windows\\Microsoft.Net\\assembly"
]

SERVICES_DENYLIST = [
    "RASMAN",
    "WinHttpAutoProxySvc",
    "gpsvc",
    "CryptSvc"
]

NORMALIZED_PATHS = {
    "c:\\windows": "%WINDIR%",
    "c:\\users\\<USER>\\appdata\\local": "%LocalAppData%",
    "c:\\users\\<USER>\\appdata\\": "%APPDATA%",
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

FILES_ENDING_DENYLIST = []

SERVICES_DENYLIST = []

# startswith
MUTEX_DENYLIST = [
    "Global\\G",
    "Local\\MSCTF",
    "CicLoadWin",
]
