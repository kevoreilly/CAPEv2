rule Cuba {
    meta:
        author = "ditekSHen"
        description = "Detects Cuba ransomware"
        cape_type = "Cuba Payload"
    strings:
        $s1 = ".cuba" fullword wide
        $s2 = "\\\\%d.%d.%d.%d" fullword wide
        $s3 = "!!FAQ for Decryption!!.txt" fullword wide
        $s4 = "vmcompute" fullword wide
        $s5 = "MSExchange" wide
        $s6 = "glocal" fullword wide
        $s7 = "network" fullword wide
        $s8 = "\\$Recycle.Bin\\" fullword wide
        $s9 = "NetShareEnum" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
