rule RansomEXX {
    meta:
        author = "ditekshen"
        description = "Detects RansomEXX ransomware"
        cape_type = "RansomEXX Payload"
    strings:
        $id = "ransom.exx" ascii
        $s1 = "!TXDOT_READ_ME!.txt" fullword wide
        $s2 = "debug.txt" fullword wide
        $s3 = ".txd0t" fullword wide
        $s4 = "crypt_detect" fullword wide
        $s5 = "powershell.exe" fullword wide
        $s6 = "cipher.exe" fullword ascii wide
        $s7 = "?ReflectiveLoader@@" ascii
    condition:
      uint16(0) == 0x5a4d and (($id and 3 of ($s*)) or all of ($*))
}

rule RansomExxNIX {
    meta:
        author = "ditekshen"
        description = "Detects RansomEXX ransomware"
        cape_type = "RansomEXX Payload"
    strings:
        $c1 = "crtstuff.c" fullword ascii
        $c2 = "cryptor.c" fullword ascii
        $c3 = "ransomware.c" fullword ascii
        $c4 = "logic.c" fullword ascii
        $c5 = "enum_files.c" fullword ascii
        $c6 = "readme.c" fullword ascii
        $c7 = "ctr_drbg.c" fullword ascii

        $s1 = "regenerate_pre_data" fullword ascii
        $s2 = "g_RansomHeader" fullword ascii
        $s3 = "CryptOneBlock" fullword ascii
        $s4 = "RansomLogic" fullword ascii
        $s5 = "CryptOneFile" fullword ascii
        $s6 = "encrypt_worker" fullword ascii
        $s7 = "list_dir" fullword ascii
        $s8 = "ctr_drbg_update_internal" fullword ascii
    condition:
        uint16(0) == 0x457f and (5 of ($s*) or 6 of ($s*) or (3 of ($c*) and 3 of ($s*)))
}
