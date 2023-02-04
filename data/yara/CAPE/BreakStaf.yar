rule BreakStaf {
    meta:
        author = "ditekSHen"
        description = "Detects BreakStaf ransomware"
        cape_type = "BreakStaf Payload"
    strings:
        $s1 = "C:\\Program files" wide
        $s2 = "C:\\Program files (x86)" wide
        $s3 = "C:\\System Volume Information" wide
        $s4 = "C:\\$Recycle.Bin" wide
        $s5 = "C:\\Windows" wide
        $s6 = ".?AVRandomNumberGenerator@Crypto" ascii
        $s7 = ".?AV?$SymmetricCipherFinal@" ascii
        $s8 = ".breakstaf" fullword wide nocase
        $s9 = "readme.txt" fullword wide nocase
        $s10 = ".VHD" fullword wide nocase
        $s11 = ".vhdx" fullword wide nocase
        $s12 = ".BAK" fullword wide nocase
        $s13 = ".BAC" fullword wide nocase
    condition:
        uint16(0) == 0x5a4d and 12 of them
}
