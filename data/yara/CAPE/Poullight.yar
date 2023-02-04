rule Poullight {
    meta:
        author = "ditekSHen"
        description = "Poullight infostealer payload"
        cape_type = "Poullight Payload"
    strings:
        $s1 = "zipx" fullword wide
        $s2 = "{0}Windows Defender.exe" fullword wide
        $s3 = "pll_test" fullword wide
        $s4 = "loginusers.vdf" wide
        $s5 = "Stealer by Nixscare" wide
        $s6 = "path_lad" fullword ascii
        $s7 = "<CheckVM>" ascii
        $s8 = "Poullight.Properties" ascii
        $s9 = "</ulfile>" fullword wide
        $s10 = "{0}processlist.txt" fullword wide
        $s11 = "{0}Browsers\\Passwords.txt" fullword wide
    condition:
        uint16(0) == 0x5a4d and 7 of them
}
