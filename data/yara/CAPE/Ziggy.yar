rule Ziggy {
    meta:
        author = "ditekSHen"
        description = "Detects Ziggy ransomware"
        cape_type = "Ziggy Payload"
    strings:
        $id1 = "/Ziggy Info;component/mainwindow.xaml" fullword wide
        $id2 = "AZiggy Info, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
        $id3 = "Ziggy Ransomware" fullword wide
        $id4 = "clr-namespace:Zeggy" fullword ascii
        $s1 = "GetCooldown" fullword ascii
        $s2 = "checkCommandMappings" fullword ascii
        $s3 =  "add_OnExecuteCommand" fullword ascii
        $s4 = "MindLated.jpg" fullword wide
        $s5 = "http://fixfiles.xyz/ziggy/api/info.php?id=" fullword wide
        $s6 = "Reamaining time:" fullword wide
        $msg1 = "<:In case of no answer in 12 hours write us to this e-mail" ascii
        $msg2 = "Free decryption as guarantee" fullword ascii
        $msg3 = "# Do not try to decrypt your data using third party software, it may cause permanent data loss" ascii
        $msg4 = "# Decryption of your files with the help of third parties may cause increased price (they add their fee to our) or you can becom" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($id*) or 4 of ($s*) or 3 of ($msg*))
}
