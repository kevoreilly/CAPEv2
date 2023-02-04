rule zgRAT {
    meta:
        author = "ditekSHen"
        description = "Detects zgRAT"
        cape_type = "zgRAT Payload"
    strings:
        $s1 = "file:///" fullword wide
        $s2 = "{11111-22222-10009-11112}" fullword wide
        $s3 = "{11111-22222-50001-00000}" fullword wide
        $s4 = "get_Module" fullword ascii
        $s5 = "Reverse" fullword ascii
        $s6 = "BlockCopy" fullword ascii
        $s7 = "ReadByte" fullword ascii
        $s8 = { 4c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00
                00 0b 46 00 69 00 6e 00 64 00 20 00 00 13 52 00
                65 00 73 00 6f 00 75 00 72 00 63 00 65 00 41 00
                00 11 56 00 69 00 72 00 74 00 75 00 61 00 6c 00
                20 00 00 0b 41 00 6c 00 6c 00 6f 00 63 00 00 0d
                57 00 72 00 69 00 74 00 65 00 20 00 00 11 50 00
                72 00 6f 00 63 00 65 00 73 00 73 00 20 00 00 0d
                4d 00 65 00 6d 00 6f 00 72 00 79 00 00 0f 50 00
                72 00 6f 00 74 00 65 00 63 00 74 00 00 0b 4f 00
                70 00 65 00 6e 00 20 00 00 0f 50 00 72 00 6f 00
                63 00 65 00 73 00 73 00 00 0d 43 00 6c 00 6f 00
                73 00 65 00 20 00 00 0d 48 00 61 00 6e 00 64 00
                6c 00 65 00 00 0f 6b 00 65 00 72 00 6e 00 65 00
                6c 00 20 00 00 0d 33 00 32 00 2e 00 64 00 6c 00
                6c }
    condition:
        uint16(0) == 0x5a4d and all of them
}
