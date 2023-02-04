rule BlackByte {
    meta:
        author = "ditekSHen"
        description = "Detect / Hunt BlackByte ransomware"
        cape_type = "BlackByte Payload"
    strings:
        $s1 = "WalkDirAndEncrypt" ascii wide nocase
        $s2 = "FileEncrypt" ascii wide nocase
        $s3 = "BlackByte." ascii wide nocase
        $s4 = "EnumerateDirAndEncrypt" ascii wide nocase
        $s5 = "Dismount-DiskImage" ascii wide nocase
        $s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
