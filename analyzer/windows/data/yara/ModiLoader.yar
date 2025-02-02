rule ModiLoader
{
    meta:
        author = "kevoreilly"
        description = "ModiLoader detonation shim"
        cape_options = "exclude-apis=NtAllocateVirtualMemory:NtProtectVirtualMemory"
        hash = "1f0cbf841a6bc18d632e0bc3c591266e77c99a7717a15fc4b84d3e936605761f"
    strings:
        $epilog1 = {81 C2 A1 03 00 00 87 D1 29 D3 33 C0 5A 59 59 64 89 10 68}
        $epilog2 = {6A 00 6A 01 8B 45 ?? 50 FF 55 ?? 33 C0 5A 59 59 64 89 10 68}
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule ModiLoaderOld {
    meta:
        author = "ditekSHen"
        description = "ModiLoader detonation shim"
        cape_options = "ntdll-protect=0"
    strings:
        $x1 = "*()%@5YT!@#G__T@#$%^&*()__#@$#57$#!@" fullword wide
        $x2 = "dntdll" fullword wide
        $x3 = "USERPROFILE" fullword wide
        $s1 = "%s, ProgID: \"%s\"" ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $s3 = "responsetext" ascii
        $s4 = "C:\\Users\\Public\\" ascii
        $s5 = "[InternetShortcut]" fullword ascii
        $c1 = "start /min powershell -WindowStyle Hidden -inputformat none -outputformat none -NonInteractive -Command \"Add-MpPreference -ExclusionPath 'C:\\Users'\" & exit" ascii  nocase
        $c2 = "mkdir \"\\\\?\\C:\\Windows \"" ascii nocase
        $c3 = "mkdir \"\\\\?\\C:\\Windows \\System32\"" ascii nocase
        $c4 = "ECHO F|xcopy \"" ascii nocase
        $c5 = "\"C:\\Windows \\System32\" /K /D /H /Y" ascii nocase
        $c6 = "ping 127.0.0.1 -n 6 > nul" ascii nocase
        $c7 = "del /q \"C:\\Windows \\System32\\*\"" ascii nocase
        $c8 = "rmdir \"C:\\Windows \\System32\"" ascii nocase
        $c9 = "rmdir \"C:\\Windows \"" ascii nocase
        $g1 = "powershell" ascii nocase
        $g2 = "mkdir \"\\\\?\\C:\\" ascii nocase
        $g3 = "\" /K /D /H /Y" ascii nocase
        $g4 = "ping 127.0.0.1 -n" ascii nocase
        $g5 = "del /q \"" ascii nocase
        $g6 = "rmdir \"" ascii nocase
    condition:
        uint16(0) == 0x5a4d and
        (
            (2 of ($x*) and (all of ($g*) or (2 of ($s*) and 2 of ($c*)))) or
            (all of ($s*) and (2 of ($c*) or all of ($g*))) or
            (4 of ($c*) and (1 of ($x*) or 2 of ($s*))) or
            (all of ($g*) and 4 of ($c*)) or
            13 of them
        )         
}
