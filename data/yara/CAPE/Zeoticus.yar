rule Zeoticus {
    meta:
        author = "ditekSHen"
        description = "Detects Zeoticus ransomware"
        cape_type = "Zeoticus Payload"
    strings:
        $s1 = "Dear %s" fullword wide
        $s2 = "\\??\\UNC\\%s\\%s\\" wide
        $s3 = "\\\\%ws\\admin$\\%ws" wide
        $s4 = "%s /node:\"%ws\" /user:\"%ws\" /password:" wide
        $s5 = "process call create" wide
        $s6 = ">----===Zeoticus" ascii
        $s7 = "ZEOTICUSV2" ascii
        $s8 = "GetExtendedTcpTable" fullword ascii
        $s9 = "SHAMROckSWTF" ascii
        $s10 = "NTDLL.RtlAllocateHeap" fullword ascii
        $s11 = ".pandora" fullword wide
        $s12 = { 70 00 20 00 72 00 20 00 69 00 20 00 76 00 20 00 65 00 20 00 74 }
        $pdb = "_cryptor\\shell_gen\\Release\\" ascii
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or ($pdb))
}
