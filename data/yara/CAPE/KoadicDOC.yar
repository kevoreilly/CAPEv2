rule KoadicDOC {
    meta:
        author = "ditekshen"
        description = "Koadic post-exploitation framework document payload"
        cape_type = "KoadicDOC payload"
    strings:
        $s1 = "&@cls&@set" ascii
        $s2 = /:~\d+,1%+/ ascii
        $s3 = "Header Char" fullword wide
        $s4 = "EMBED Package" ascii
        $b1 = ".bat\"%" ascii
        $b2 = ".bat');\\\"%" ascii
        $b3 = ".bat',%" ascii
    condition:
        uint16(0) == 0xcfd0 and all of ($s*) and 2 of ($b*)
}
