rule Satana {
    meta:
        author = "ditekSHen"
        description = "Detects Satana ransomware"
        cape_type = "Satana Payload"
    strings:
        $bf1 = "Try Decrypt: uc_size = %d, c_size = %d" ascii
        $bf2 = "dwMailSelector = %d  dwBtcSelector = %d" ascii
        $bf3 = "%s: Error DecB: 0x%X" ascii
        $bf4 = "MBR written to Disk# %d" ascii
        $bf5 = "!SATANA!" ascii wide nocase
        $bf6 = "1 -th start" fullword ascii
        $bf7 = "id=%d&code=%d&sdata=%d.%d.%d %d %d %s %s %d&name=%s&md5=%s&dlen=%s" ascii
        $bf8 = "threadAdminFlood: %s %s %s" wide
        $bf9 = "%s: NET RES FOUND: %s" wide
    condition:
        (uint16(0) == 0x5a4d and 4 of ($bf*)) or (5 of ($bf*))
}
