rule Nitro {
    meta:
        author = "ditekSHen"
        description = "Detects Nitro Ransomware"
        cape_type = "Nitro Payload"
    strings:
        $x1 = ".givemenitro" wide
        $x2 = "Nitro Ransomware" ascii wide
        $x3 = "\\NitroRansomware.pdb" ascii
        $x4 = "NitroRansomware" ascii wide nocase
        $s1 = "Valid nitro code was received" wide
        $s2 = "discord nitro" ascii wide nocase
        $s3 = "Starting file encryption" wide
        $s4 = "NR_decrypt.txt" wide
        $s5 = "open it unless you have the decryption key." ascii
        $s6 = "<EncryptAll>b__" ascii
        $s7 = "<DecryptAll>b__" ascii
        $s8 = "DECRYPT_PASSWORD" fullword ascii
        $s9 = "IsEncrypted" fullword ascii
        $s10 = "CmdProcess_OutputDataReceived" fullword ascii
        $s11 = "encryptedFileLog" fullword ascii
        $s12 = "Encrypting:" fullword wide
        $s13 = "decryption key. If you do so, your files may get corrupted" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or (3 of ($s*) and 1 of ($x*)) or (7 of ($s*)))
}
