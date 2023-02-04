rule BlackMatter {
    meta:
        author = "ditekSHen"
        description = "Detects BlackMatter ransomware"
        cape_type = "BlackMatter Payload"
    strings:
        $s1 = "C:\\Windows\\System32\\*.drv" fullword wide
        $s2 = "NYbr-Vk@" fullword ascii
        $s3 = ":7:=:H:Q:W:\\:b:&;O;^;v;" fullword ascii
        $o1 = { b0 34 aa fe c0 e2 fb b9 03 }
        $o2 = { fe 00 ff 75 08 ff 75 0c ff b5 d8 fe ff ff ff b5 }
        $o3 = { 6a 00 ff 75 0c ff b5 d8 fe ff ff ff b5 dc fe ff }
        $o4 = { ff 75 08 ff 75 0c ff b5 d8 fe ff ff ff b5 dc fe }
        $o5 = { 53 56 57 8d 85 70 ff ff ff 83 c0 0f 83 e0 f0 89 }
        $o6 = { c7 85 68 ff ff ff 00 04 00 00 8b 85 6c ff ff ff }
        //SOFTWARE\Microsoft\Crypt
        //Volume{
        //*recycle*
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) and all of ($o*))
}
