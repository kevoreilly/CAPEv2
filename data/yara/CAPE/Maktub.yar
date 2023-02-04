rule Maktub {
    meta:
        author = "ditekSHen"
        description = "Detects Maktub ransomware"
        cape_type = "Maktub Payload"
    strings:
        $s1 = "Content-Disposition: attachment; filename=" ascii
        $s2 = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" fullword ascii
        $s3 = "/tor/status-vote/current/consensus" ascii
        $s4 = "/tor/server/fp/" ascii
        $s5 = "/tor/rendezvous2/" ascii
        $s6 = "404 Not found" fullword ascii
        $s7 = /_request@\d+/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
