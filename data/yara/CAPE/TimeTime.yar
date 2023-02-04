rule TimeTime {
    meta:
        author = "ditekSHen"
        description = "Detects TimeTime ransomware"
        cape_type = "TimeTime Payload"
    strings:
        $s1 = "@_DECRYPTOR_@" ascii wide
        $s2 = "@__RECOVER_YOUR_FILES__@" wide
        $s3 = "\\TimeTime.pdb" ascii
        $s4 = "runCommand" fullword ascii
        $s5 = "decryptor_file_name" fullword ascii
        $s6 = "encryption_hiding_process" fullword ascii
        $s7 = "admin_hiding_process" fullword ascii
        $s8 = "security_vaccine" fullword ascii
        $s9 = "EncrFiles_Load" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
