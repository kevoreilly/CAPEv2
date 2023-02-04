rule ObliqueRAT {
    meta:
        author = "ditekSHen"
        description = "ObliqueRAT payload"
        cape_type = "ObliqueRAT Payload"
    strings:
        $s1 = "C:\\ProgramData\\auto.txt" fullword ascii
        $s2 = "C:\\ProgramData\\System\\Dump\\" fullword ascii
        $s3 = "C:\\ProgramData\\a.txt" fullword ascii
        $s4 = "Oblique" fullword ascii
        $s5 = /(Removable|Hard|Network|CD|RAM)\sDisk\|/ ascii
        $s6 = "backed" fullword ascii
        $s7 = "restart" fullword ascii
        $s8 = "kill" fullword ascii
        $s9 = /(John|JOHN|Test|TEST|Johsnson|Artifact|Vince|Serena|Lisa|JOHNSON|VINCE|SERENA)/ ascii nocase
        $v1 = "C:\\ProgramData" fullword ascii
        $v2 = "auto" fullword ascii
        $v3 = "plit" fullword ascii
        $v4 = ":image/jpeg" fullword wide
    condition:
        uint16(0) == 0x5a4d and 8 of them
}
