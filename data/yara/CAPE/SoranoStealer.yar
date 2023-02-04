rule SoranoStealer {
    meta:
        author = "ditekSHen"
        description = "Detects SoranoStealer / HogGrabber"
        cape_type = "SoranoStealer Payload"
    strings:
        $x1 = "OiCuntJollyGoodDayYeHavin_" ascii
        $x2 = { 00 56 4d 50 72 6f 74 65 63 74 00 52 65 61 63 74
                6f 72 00 64 65 34 66 75 63 6b 79 6f 75 00 42 61
                62 65 6c 4f 62 66 75 73 63 61 74 6f 72 41 74 74
                72 69 62 75 74 65 00 43 72 79 74 70 6f 4f 62 66
                75 73 63 61 74 6f 72 00 }
        $x3 = { 00 4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c
                69 61 74 68 00 42 65 64 73 2d 50 72 6f 74 6f 72 00 }
        $s1 = ".Binaries.whysosad" ascii
        $s2 = "Adminstrator permissons are required" wide
        $s3 = "12:03:33:4A:04:AF" fullword wide
        $s4 = "RemoveEXE" fullword ascii
        $s5 = "$340becfa-1688-4c32-aa49-30fdb4005e4b" fullword ascii
        $s6 = "$99cffbcc-6ad7-4d32-bd1f-450967cf4a6b" fullword ascii
        $s7 = "\"cam\": " ascii
        $s8 = " - 801858595527371999762718088" fullword ascii
        $s9 = "  - 96188142294460126639341306" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (2 of ($x*) and 3 of ($s*)) or 5 of ($s*))
}
