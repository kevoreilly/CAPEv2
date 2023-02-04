rule Fabookie {
     meta:
        author = "ditekSHen"
        description = "Detects Fabookie / ElysiumStealer"
        cape_type = "Fabookie Infostealer Payload"
    strings:
        $s1 = "rwinssyslog" fullword wide
        $s2 = "_kasssperskdy" fullword wide
        $s3 = "[Title:%s]" fullword wide
        $s4 = "[Execute]" fullword wide
        $s5 = "[Snapshot]" fullword wide
        $s6 = "Mozilla/4.0 (compatible)" fullword wide
        $s7 = "d-k netsvcs" fullword wide
        $s8 = "facebook.websmails.com" fullword wide
        $s9 = "CUdpClient::Start" fullword ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x0805) and 6 of them
}
