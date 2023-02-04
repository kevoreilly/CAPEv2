rule DoejoCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects DoejoCrypt / DearCry ransomware"
        cape_type = "DoejoCrypt Payload"
    strings:
        $s1 = "DEARCRY!" fullword ascii
        $s2 = ".CRYPT" fullword ascii
        $s3 = "\\EncryptFile -svcV2\\" ascii
        $s4 = "please send me the following hash!" ascii
        $s5 = "dear!!!" fullword ascii
        $s6 = "/readme.txt" fullword ascii
        $o1 = { c3 8b 65 e8 c7 45 fc fe ff ff ff 8b b5 f4 e9 ff }
        $o2 = { 0f 8c 27 ff ff ff 33 db 57 e8 7b 36 00 00 eb 0a }
        $o3 = { 0f 8c 2a ff ff ff 53 57 e8 b7 42 00 00 8b 4c 24 }
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) or (all of ($o*) and (2 of ($s*)))
}
