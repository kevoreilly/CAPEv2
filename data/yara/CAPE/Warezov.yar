rule Warezov {
    meta:
        author = "ditekSHen"
        description = "Detects Warezov worm/downloader"
        cape_type = "Warezov Payload"
    strings:
        $s1 = "ft\\Windows\\CurrentVersion\\Run" wide
        $s2 = "DIR%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s3 = "%WINDIR%\\sqhos32.wmf" wide
        $s4 = "Accept: */*" fullword ascii
        $s5 = "Range: bytes=" fullword ascii
        $s6 = "module.exe" fullword ascii
        $s7 = { 25 73 25 73 2e 25 73 ?? ?? 22 22 26 6c 79 79 56 00 00 00 00 25 73 25 30 34 64 25 30 32 64 25 30 32 64 00 }
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
