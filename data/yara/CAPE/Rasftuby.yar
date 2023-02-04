rule Rasftuby {
    meta:
        author = "ditekSHen"
        description = "Detects Rasftuby/DarkCrystal infostealer"
        cape_type = "Rasftuby Payload"
    strings:
        $s1 = "/DCRS/main.php?data=active" fullword ascii wide
        $s2 = "/socket.php?type=__ds_" ascii wide
        $s3 = "/uploader.php" fullword ascii wide
        $s4 = "del \\\"%USERPROFILE%\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\System.lnk\\\"" fullword ascii wide
        $s5 = "Host:{0},Port:{1},User:{2},Pass:{3}<STR>" fullword ascii wide
        $s6 = "keyloggerstart_status" fullword ascii wide
        $s7 = "keyloggerstop_status" fullword ascii wide
        $s8 = "[PRINT SCREEN]" fullword ascii wide
        $s9 = "DCS.Internal" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of ($s*)
}
