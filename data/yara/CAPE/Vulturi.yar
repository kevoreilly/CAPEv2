rule Vulturi {
    meta:
        author = "ditekSHen"
        description = "Detects Vulturi infostealer"
        cape_type = "Vulturi Infostealer Payload"
    strings:
        $x1 = "Vulturi_" ascii wide
        $x2 = "VulturiProject" fullword ascii
        $s1 = { 5b 00 2d 00 5d 00 20 00 53 00 65 00 72 00 76 00
               65 00 72 00 20 00 ?? ?? 20 00 69 00 73 00 20 00
               6f 00 66 00 66 00 6c 00 69 00 6e 00 65 00 2e 00
               2e 00 2e 00 00 ?? 5b 00 2b 00 5d 00 20 00 53 00
               65 00 72 00 76 00 65 00 72 00 20 00 00 ?? ?? 00
               69 00 73 00 20 00 6f 00 6e 00 6c 00 69 00 6e 00
               65 00 }
        $s2 = "Writing is not alowed" wide
        $s3 = "System\\ProcessList.txt" fullword wide
        $s4 = "[X] GetSSL ::" fullword wide
        $s5 = "Failed to steal " wide
        $s6 = "StealerStub" fullword ascii
        $s7 = "/C chcp 65001 && netsh" wide
        $n1 = "fetch_options" fullword wide
        $n2 = "send_report" fullword wide
        $n3 = "?username=" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and any of them) or all of ($n*) or 5 of ($s*) or (1 of ($n*) and 3 of ($s*)))
}
