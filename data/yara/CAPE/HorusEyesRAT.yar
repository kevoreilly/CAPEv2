rule HorusEyesRAT {
    meta:
        author = "ditekSHen"
        description = "Detects HorusEyesRAT"
        cape_type = "HorusEyesRAT Payload"
    strings:
        $x1 = "\\HorusEyesRat-" ascii
        $x2 = "\\HorusEyesRat.pdb" ascii
        $x3 = "get_horus_eye" ascii
        $s1 = "get_Type_Packet" fullword ascii
        $s2 = "PacketLib" fullword ascii nocase
        $s3 = "System.Net.Sockets" fullword ascii
        $s4 = "PROCESS_MODE_BACKGROUND_BEGIN" fullword ascii
        $s5 = "EXECUTION_STATE" fullword ascii
        $s6 = /Plugins\\[A-Z]{2}.dll/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 3 of ($s*)) or (4 of ($s*) and #s6 > 4))
}
