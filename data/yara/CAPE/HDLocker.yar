rule HDLocker {
    meta:
        author = "ditekSHen"
        description = "Detects HDLocker ransomware"
        cape_type = "HDLocker Payload"
    strings:
        $s1 = "HDLocker_" fullword ascii
        $s2 = ".log" fullword ascii
        $s3 = "Scripting.FileSystemObject" fullword ascii
        $s4 = "Boot" fullword ascii
        $s5 = "hellwdo" fullword ascii
        $s6 = "blackmoon" fullword ascii
        $s7 = "BlackMoon RunTime Error:" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
