rule Godzilla {
    meta:
        author = "ditekSHen"
        description = "Detects Godzilla loader"
        cape_type = "Godzilla Loader Payload"
    strings:
        $x1 = "MSVBVM60.DLL" fullword ascii
        $x2 = "Loginserver8" fullword ascii
        $x3 = "Proflogger7" fullword ascii
        $s1 = "Badgeless5" fullword ascii
        $s2 = "Montebrasite3" fullword ascii
        $s3 = "Atelomyelia4" fullword ascii
        $s4 = "Xxencoded5" fullword ascii
        $s5 = "Garneau2" fullword ascii
        $s6 = "Hypostasis0" fullword ascii
        $s7 = "Piarhemia4" fullword ascii
        $s8 = "Foredestine8" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of ($x*) and 2 of ($s*)
}
