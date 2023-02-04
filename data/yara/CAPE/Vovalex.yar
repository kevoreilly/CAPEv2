rule Vovalex {
    meta:
        author = "ditekSHen"
        description = "Detects Vovalex ransomware"
        cape_type = "Vovalex Payload"
    strings:
        $s1 = "README.VOVALEX.txt" fullword ascii
        $s2 = "\\src\\phobos\\std\\" ascii
        $s3 = "LoadLibraryA(\"Advapi32.dll\")" fullword ascii
        $s4 = "Failed to spawn process \"" fullword ascii
        $s5 = "=== Bypassed ===" fullword ascii
        $s6 = "If you don't know where to buy" ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
