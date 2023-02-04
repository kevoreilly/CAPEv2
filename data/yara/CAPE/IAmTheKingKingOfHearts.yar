rule IAmTheKingKingOfHearts {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing King Of Hearts payload"
        cape_type = "IAmTheKingKingofHearts Payload"
    strings:
        $s1 = "write info fail!!! GetLastError-->%u" fullword ascii
        $s2 = "LookupAccountSid Error %u" fullword ascii
        $s3 = "CreateServiceErrorID:%d" fullword ascii
        $s4 = "In ControlServiceErrorID:%d" fullword ascii
        $s5 = "In QueryServiceStatus ErrorID:%d" fullword ascii
        $s6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" fullword ascii
        $s7 = "hello%s" fullword ascii
        $s8 = "additional header failed..." fullword ascii
        $s9 = "Set Option failed errcode: %ld" fullword ascii
        $s10 = "add cookie failed..." fullword ascii

        $u1 = "Mozilla/4.0 (compatible; )" fullword ascii
        $u2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SE)" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($u*) and 4 of ($s*)) or (all of ($u*) and 3 of ($s*)) or (5 of them))
}
