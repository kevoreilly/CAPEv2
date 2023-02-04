rule BrbBot {
    meta:
        author = "ditekSHen"
        description = "Detects BrbBot"
        cape_type = "BrbBot Payload"
    strings:
        $x1 = "brbconfig.tmp" fullword ascii
        $x2 = "brbbot" fullword ascii
        $s1 = "%s?i=%s&c=%s&p=%s" fullword ascii
        $s2 = "exec" fullword ascii
        $s3 = "CONFIG" fullword ascii wide
        $s4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)" fullword ascii
        $s5 = { 43 4f 4e 46 49 47 00 00 65 6e 63 6f 64 65 00 00
                73 6c 65 65 70 00 00 00 65 78 69 74 00 00 00 00
                63 6f 6e 66 00 00 00 00 66 69 6c 65 00 00 00 00
                65 78 65 63 }
    condition:
        uint16(0) == 0x5a4d and ((all of ($x*) and 1 of ($s*)) or (1 of ($x*) and 4 of ($s*)) or all of ($s*))
}
