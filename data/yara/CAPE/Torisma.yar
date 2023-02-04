rule Torisma {
    meta:
        author = "ditekSHen"
        description = "Detects Torisma. Assocaited with Lazarus"
        cape_type = "Torisma Payload"
    strings:
        $s1 = "ACTION=PREVPAGE&CODE=C%s&RES=%d" fullword ascii
        $s2 = "ACTION=VIEW&PAGE=%s&CODE=%s&CACHE=%s&REQUEST=%d" fullword ascii
        $s3 = "ACTION=NEXTPAGE&CODE=S%s&CACHE=%s&RES=%d" fullword ascii
        $s4 = "Your request has been accepted. ClientID: {" ascii
        $s5 = "Proxy-Connection: Keep-Alive" fullword wide
        $s6 = "Content-Length: %d" fullword wide
        $o0 = { f7 f9 8b c2 89 44 24 34 48 63 44 24 34 48 8b 4c }
        $o1 = { 48 c7 00 ff ff ff ff 48 8b 84 24 90 }
        $o2 = { f3 aa 83 7c 24 30 01 75 34 c7 44 24 20 01 }
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) or (all of ($o*) and 3 of ($s*))
}
