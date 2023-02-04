rule ReverseRAT {
     meta:
        author = "ditekSHen"
        description = "Detects ReverseRAT"
        cape_type = "ReverseRAT Payload"
    strings:
        $pdb1 = "\\ReverseRat.pdb" ascii nocase
        $pdb2 = "\\ReverseRat\\obj\\" ascii nocase
        $s1 = "processCmd" fullword ascii
        $s2 = "CmdOutputDataHandler" fullword ascii
        $s3 = "sendingProcess" fullword ascii
        $s4 = "SetStartup" fullword ascii
        $s5 = "RunServer" fullword ascii
        $s6 = "_OutputDataReceived" ascii
        $s7 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00
                00 03 0a 00 00 13 74 00 65 00 72 00 6d 00
                69 00 6e 00 61 00 74 00 65 00 00 09 65 00
                78 00 69 00 74 00 }
    condition:
        uint16(0) == 0x5a4d and ((1 of ($pdb*) and 2 of ($s*)) or 5 of ($s*))
}
