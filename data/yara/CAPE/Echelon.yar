rule Echelon {
    meta:
        author = "ditekshen"
        description = "Echelon information stealer payload"
        cape_type = "Echelon payload"
    strings:
        $s1 = "<GetStealer>b__" ascii
        $s2 = "clearMac" fullword ascii
        $s3 = "path2save" fullword ascii
        $s4 = "Echelon_Size" fullword ascii
        $s5 = "Echelon Stealer by" wide
        $s6 = "get__masterPassword" fullword ascii
        $s7 = "DomainDetect" fullword ascii
        $s8 = "[^\\u0020-\\u007F]" fullword wide
        $s9 = "/sendDocument?chat_id=" wide
        $s10 = "//setting[@name='Password']/value" wide
        $s11 = "Passwords_Mozilla.txt" fullword wide
        $s12 = "Passwords_Edge.txt" fullword wide
        $s13 = "@madcod" ascii wide
        $pdb = "\\Echelon-Stealer-master\\obj\\Release\\Echelon.pdb" ascii
    condition:
        (uint16(0) == 0x5a4d and (8 of ($s*) or $pdb)) or (8 of ($s*) or $pdb)
}
