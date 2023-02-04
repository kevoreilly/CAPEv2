rule MountLocker {
    meta:
        author = "ditekSHen"
        description = "Detects MountLocker ransomware"
        cape_type = "MountLocker Payload"
    strings:
        $s1 = "] locker.dir.check > " ascii wide
        $s2 = "] locekr.kill." ascii wide
        $s3 = "] locker.worm" ascii wide
        $s4 = "%CLIENT_ID%" fullword ascii
        $s5 = "RecoveryManual.html" ascii wide
        $s6 = "RECOVERY MANUAL" ascii
        $s7 = ".ReadManual.%0.8X" ascii wide
        $s8 = "/?cid=%CLIENT_ID%" ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}
