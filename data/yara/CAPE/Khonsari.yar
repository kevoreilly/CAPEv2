rule Khonsari {
    meta:
        author = "ditekSHen"
        description = "Detects Khonsari ransomware"
        cape_type = "Khonsari Payload"
    strings:
        $x1 = ".khonsari" fullword wide nocase
        $s1 = "Encrypt" fullword ascii
        $s2 = "CreateEncryptor" fullword ascii
        $s3 = "GenerateKey" fullword ascii
        $s4 = "277e5e6a-4da6-4138-97fa-3fecbdad0176" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 2 of ($s*)) or (all of ($s*)))
}
