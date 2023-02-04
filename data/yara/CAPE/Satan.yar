rule Satan {
    meta:
        author = "ditekSHen"
        description = "Detects Satan ransomware"
        cape_type = "Satan Payload"
    strings:
        $s1 = "S:(ML;;NRNWNX;;;LW)" fullword wide
        $s2 = "recycle.bin" fullword wide
        $s3 = "tmp_" fullword wide
        $s4 = "%s%08x.%s" fullword wide
        $s5 = "\"%s\" %s" fullword wide
        $s6 = "/c \"%s\"" fullword wide
        $s7 = "Global\\" fullword wide
        $s8 = "rd /S /Q \"%s\"" fullword ascii
        $s9 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)" fullword ascii
        $e1 = "*pdf*" fullword wide
        $e2 = "*rtf*" fullword wide
        $e3 = "*doc*" fullword wide
        $e4 = "*docx*" fullword wide
        $e5 = "*xlsx*" fullword wide
        $e6 = "*pptx*" fullword wide
        $e7 = "*moneywell*" fullword wide
        $o1 = { 56 8d 54 24 34 b9 9e f0 ea be e8 c1 f9 ff ff 8d }
        $o2 = { b9 34 f6 40 00 e8 ea 0b 00 00 85 c0 0f 84 91 }
        $o3 = { 53 8d 84 24 34 01 00 00 b9 01 00 00 80 50 a1 64 }
    condition:
        uint16(0) == 0x5a4d and ((8 of ($s*) and 4 of ($e*)) or all of ($s*) or (all of ($e*) and 5 of ($s*)) or (all of ($o*) and 8 of them))
}
