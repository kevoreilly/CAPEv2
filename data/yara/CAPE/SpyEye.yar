rule SpyEye {
    meta:
        author = "ditekSHen"
        description = "Detects SpyEye"
        cape_type = "SpyEye Payload"
    strings:
        $x1 = "_CLEANSWEEP_" ascii wide
        $x2 = "config.datUT" fullword ascii
        $x3 = "webinjects.txtUT" fullword ascii
        $s1 = "confirm:processCommand" fullword ascii
        $s2 = "Smth wrong with navigate to REF-PAGE (err code: %d). 0_o" fullword ascii
        $s3 = "(UTC%s%2.2f) %s" fullword wide
        $s4 = "M\\F;u`r" fullword ascii
        $s5 = "]YH0%Yn" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 1 of ($s*)))
}
