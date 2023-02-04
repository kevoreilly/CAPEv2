rule SilentMoon {
    meta:
        author = "ditekSHen"
        description = "Detects SilentMoon"
        cape_type = "SilentMoon Payload"
    strings:
        $s1 = "\\\\.\\Global\\PIPE\\" fullword wide
        $s2 = "REMOTE_NS:ERROR:%d" fullword ascii
        $s3 = "REMOTE:ERROR:%d" fullword ascii
        $s4 = "COMNAP,COMNODE,SQLQUERY,SPOOLSS,LLSRPC,browser" fullword wide
        $s5 = "Mem alloc err" fullword ascii
        $s6 = "block %d: crc = 0x%08x, combined CRC = 0x%08x, size = %d" ascii
        $x1 = "ACTION:UNSUPPORTED" fullword ascii
        $x2 = "?ServiceMain@@YAXKPAPA_W@Z" fullword ascii
        $x3 = "?ServiceCtrlHandler@@YGKKKPAX0@Z" fullword ascii
        $x4 = "%d socks, %d sorted, %d scanned" ascii
        $x5 = "GoldenSky" fullword wide
        $x6 = "SilentMoon" fullword wide
        $x7 = "internalstoragerpc" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 3 of ($x*))
}
