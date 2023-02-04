rule Alfonoso {
    meta:
        author = "ditekSHen"
        description = "Detects Alfonoso / Shurk / HunterStealer infostealer"
        cape_type = "Alfonso Infostealer Payload"
    strings:
        $s1 = "%s\\etilqs_" fullword ascii
        $s2 = "SELECT name, rootpage, sql FROM '%q'.%s" fullword ascii
        $s3 = "%s-mj%08X" fullword ascii
        $s4 = "| Site:" ascii
        $s5 = "| Login:" ascii
        $s6 = "| Password:" ascii
        $s7 = "| BUILD NAME:" ascii
        $s8 = "recursive_directory_iterator" ascii
        $s9 = { 2e 7a 69 70 00 00 00 00 2e 7a 6f 6f 00 00 00 00
                2e 61 72 63 00 00 00 00 2e 6c 7a 68 00 00 00 00
                2e 61 72 6a 00 00 00 00 2e 67 7a 00 2e 74 67 7a
                00 00 00 00 }
        $s10 = "Shurk Steal" fullword ascii
        $s11 = ":memory:" fullword ascii
        $s12 = "current_path()" fullword ascii
        $s13 = "vtab:%p:%p" fullword ascii
        $f1 = "chatlog.txt" ascii
        $f2 = "servers.fav" ascii
        $f3 = "\\USERDATA.DAT" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (8 of ($s*) or (6 of ($s*) and 2 of ($f*)) or (all of ($f*) and 5 of ($s*)))
}
