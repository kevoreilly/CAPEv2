rule Farfli {
    meta:
        author = "ditekSHen"
        description = "Detects Farfli backdoor"
        cape_type = "Farfli Payload"
    strings:
        $s1 = "%ProgramFiles%\\Google\\" fullword ascii
        $s2 = "%s\\%d.bak" fullword ascii
        $s3 = "%s Win7" fullword ascii
        $s4 = "%s:%d:%s" fullword ascii
        $s5 = "C:\\2.txt" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
