rule Xorist {
    meta:
        author = "ditekSHen"
        description = "Xorist ransomware payload"
        cape_type = "Xorist Payload"
    strings:
        $x1 = { 00 4d 00 41 00 47 00 45 00 0b 00 50 00 55 00
                53 00 53 00 59 00 4c 00 49 00 43 00 4b 00 45
                00 52 00 }
        $x2 = { 30 70 33 6e 53 4f 75 72 63 33 20 58 30 72 31 35
                37 2c 20 6d 6f 74 68 65 72 66 75 63 6b 65 72 21
                00 70 75 73 73 79 6c 69 63 6b 65 72 00 2e 62 6d
                70 00 2e 00 2e 2e 00 6f 70 65 6e 00 2e 65 78 65 }
        $s1 = "\\shell\\open\\command" fullword ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
        $s3 = "CRYPTED!" fullword ascii
        $s4 = "Attention!" fullword ascii
        $s5 = "Password:" fullword ascii
        $s6 = { 43 6f 6d 53 70 65 63 00 2f 63 20 64 65 6c 20 22 00 22 20 3e 3e 20 4e 55 4c }
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 5 of ($s*) or (1 of ($x*) and 3 of ($s*)))
}
