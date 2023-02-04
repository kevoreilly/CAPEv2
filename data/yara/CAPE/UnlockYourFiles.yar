rule UnlockYourFiles {
    meta:
        author = "ditekSHen"
        description = "Detects UnlockYourFiles ransomware"
        cape_type = "UnlockYourFiles Payload"
    strings:
        $s1 = "filesx0" wide
        $s2 = "_auto_file" wide
        $s3 = "<EncyptedKey>" fullword wide
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\" wide
        $s5 = "DecryptAllFile" fullword ascii
        $s6 = "AES_Only_Decrypt_File" fullword ascii
        $m1 = "Free files decrypted" wide
        $m2 = "Restore my files" wide
        $m3 = "Type tour password..." wide
        $m4 = "files encrypted by strong password" ascii
        $m5 = "buy bitcoin" ascii
        $m6 = "Unlock File" fullword wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or 5 of ($m*) or (2 of ($s*) and 2 of ($m*)))
}
