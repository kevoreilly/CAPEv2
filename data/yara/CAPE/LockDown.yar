rule LockDown {
    meta:
        author = "ditekSHen"
        description = "Detects Lockdown / cantopen ransomware"
        cape_type = "LockDown Payload"
    strings:
        $s1 = "BgIAAACkAABSU0E" wide
        $s2 = ".cantopen" fullword wide
        $s3 = "\\HELP_DECRYPT_YOUR_FILES.txt" wide
        $s4 = "SALT" fullword wide
        $s5 = "$4e677664-9a63-458e-a365-deb792509557" fullword ascii
        $s6 = "CreateEncryptor" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
