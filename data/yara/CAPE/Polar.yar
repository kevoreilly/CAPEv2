rule Polar {
    meta:
        author = "ditekSHen"
        description = "Polar ransomware payload"
        cape_type = "Polar Payload"
    strings:
        $s1 = "Encrypt Failed ! ErrorMessage :" wide
        $s2 = ".locked" fullword wide
        $s3 = ".cryptd" fullword wide
        $s4 = "$SysReset" fullword wide
        $s5 = "Polar.Properties.Resources" ascii wide
        $s6 = "AES_EnDecryptor.Basement" fullword ascii
        $s7 = "RunCMDCommand" fullword ascii
        $s8 = "killerps_list" fullword ascii
        $s9 = "clearlog" fullword ascii
        $s10 = "encryptFile" fullword ascii
        $s11 = "changeBackPictrue" fullword ascii
        $pdb1 = "\\Ransomware_ALL_encode\\dir_file\\obj\\x86\\Release\\Encode.pdb" ascii
        $pdb2 = "\\Ransomware_ALL_encode\\dir_file\\obj\\x64\\Release\\Encode.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (8 of ($s*) or (1 of ($pdb*) and 2 of ($s*)))
}
