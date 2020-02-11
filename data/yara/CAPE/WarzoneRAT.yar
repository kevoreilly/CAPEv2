rule WarzoneRAT {
    meta:
        author = "ditekshen"
        description = "WarzoneRAT payload"
        cape_type = "WarzoneRAT Payload"
    strings:
        $s1_1 = "PK11_CheckUserPassword" fullword ascii
        $s1_2 = "PK11_Authenticate" fullword ascii
        $s1_3 = "PK11SDR_Decrypt" fullword ascii
        $s1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" fullword ascii
        $s1_5 = "AVE_MARIA" ascii wide
        $s1_6 = "127.0.0." ascii

        $s2_1 = "RDPClip" fullword wide
        $s2_2 = "Grabber" fullword wide
        $s2_3 = "Ave_Maria Stealer OpenSource" wide
        $s2_4 = "\\MidgetPorn\\workspace\\MsgBox.exe" wide
        $s2_5 = "@\\cmd.exe" wide
        $s2_6 = "/n:%temp%\\ellocnak.xml" wide
        $s2_7 = "Hey I'm Admin" wide

        $d1 = "softokn3.dll" fullword wide
        $d2 = "nss3.dll" fullword wide
        $d3 = "logins.json" wide
        $d4 = "Asend.db" fullword wide       
    condition:
        (uint16(0) == 0x5a4d and (4 of ($s2*) and 2 of ($d*)) or (all of ($s1*))) or ((4 of ($s1*) and 2 of ($d*)) or (all of ($s1*)))
}
