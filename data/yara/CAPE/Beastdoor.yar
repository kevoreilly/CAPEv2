rule Beastdoor {
    meta:
        author = "ditekSHen"
        description = "Detects Beastdoor backdoor"
        cape_type = "Beastdoor Backdoor Payload"
    strings:
        $s1 = "shellx.pif" fullword ascii nocase
        $s2 = "Beasty" fullword ascii
        $s3 = "* Boot:[" ascii
        $s4 = "^ Shut Down:[" ascii
        $s5 = "set cdaudio door" ascii
        $s6 = "This \"Portable Network Graphics\" image is not valid" wide
        $n1 = ".aol.com" ascii
        $n2 = "web.icq.com" ascii
        $n3 = "&fromemail=" fullword ascii
        $n4 = "&subject=" fullword ascii
        $n5 = "&Send=" fullword ascii
        $n6 = "POST /scripts/WWPMsg.dll HTTP/1.0" fullword ascii
        $n7 = "mirabilis.com" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 5 of ($n*) or (3 of ($s*) and 3 of ($n*)))
}
