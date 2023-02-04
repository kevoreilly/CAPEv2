rule Bobik {
    meta:
        author = "ditekSHen"
        description = "Detects Bobik infostealer"
        cape_type = "Bobik Payload"
    strings:
        $s1 = "@Default\\Login Data" fullword ascii
        $s2 = "@Default\\Cookies" fullword ascii
        $s3 = "@logins.json" fullword ascii
        $s4 = "@[EXECUTE]" fullword ascii
        $s5 = "@C:\\Windows\\System32\\cmd.exe" fullword ascii
        $s6 = /(CHROME|OPERA|FIREFOX)_BASED/ fullword ascii
        $s7 = "threads.nim" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
