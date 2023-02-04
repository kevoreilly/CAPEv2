rule InfoStealerUNK01 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown information stealer"
        cape_type = "Infostealer Payload"
    strings:
        $s1 = "%s\\%s\\%s-Qt" fullword wide
        $s2 = "%s\\%s.json" fullword wide
        $s3 = "*.mmd*" fullword wide
        $s4 = "%s\\%s.vdf" fullword wide
        $s5 = "%-50s %s" fullword wide
        $s6 = "dISCORD|lOCAL" fullword ascii nocase
        $s7 = "sTORAGE|LEVELDB" fullword ascii nocase
        $s8 = ".coin" fullword ascii
        $s9 = ".emc" fullword ascii
        $s10 = ".lib" fullword ascii
        $s11 = ".bazar" fullword ascii
        $s12 = "id=%d" fullword ascii
        $s13 = "2:?/v /v /v /^Y" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}
