rule Rapid {
    meta:
        author = "ditekSHen"
        description = "Detects Rapid ransomware"
        cape_type = "Rapid Payload"
    strings:
        $s1 = "encblklen" fullword ascii
        $s2 = ".rapid" fullword ascii
        $s3 = "BgIAAACkAABSU0E" ascii
        $s4 = "IFdlIHNlbmQ" ascii
        $s5 = "Software\\EncryptKeys" fullword ascii
        $s6 = "local_enc_private_key" fullword ascii
        $s7 = "local_public_key" fullword ascii
        $s8 = "How Recovery Files.txt" ascii
        $s9 = "recovery.txt" ascii
        $s10 = "thr %i run %s" fullword ascii
        $s11 = " /TN Encrypter" ascii
        $s12 = /Encrypter_\d+/ fullword ascii
        $m1 = "tell us your unique ID - ID-" ascii
        $m2 = "really want to restore your files?" ascii
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (1 of ($m*) and 4 of ($s*)))
}
