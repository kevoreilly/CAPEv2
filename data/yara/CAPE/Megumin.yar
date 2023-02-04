rule Megumin {
    meta:
        author = "ditekshen"
        description = "Megumin payload"
        cape_type = "Megumin payload"
    strings:
        $s1 = "loadpe|" fullword ascii
        $s2 = "Megumin/2.0" fullword ascii
        $s3 = "/c start /I \"\" \"" fullword ascii
        $s4 = "jsbypass|" fullword ascii

        $cnc1 = "Mozilla/5.0 (Windows NT 6.1) Megumin/2.0" fullword ascii
        $cnc2 = "/cdn-cgi/l/chk_jschl?s=" fullword ascii
        $cnc3 = "/newclip?hwid=" fullword ascii
        $cnc4 = "/isClipper" fullword ascii
        $cnc5 = "/task?hwid=" fullword ascii
        $cnc6 = "/completed?hwid=" fullword ascii
        $cnc7 = "/gate?hwid=" fullword ascii
        $cnc8 = "/addbot?hwid=" fullword ascii

        $pdb = "\\MeguminV2\\Release\\MeguminV2.pdb" ascii
    condition:
        (uint16(0) == 0x5a4d and (all of ($s*) or 5 of ($cnc*) or $pdb)) or 11 of them
}
