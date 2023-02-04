rule Guidlma {
    meta:
        author = "ditekSHen"
        description = "Detects Guildma"
        cape_type = "Guildma Payload"
    strings:
        $v1_1 = "marxvxinhhm98.dll" fullword wide
        $v1_2 = "marxvxinhhmxa.gif" fullword wide
        $v1_3 = "marxvxinhhmxb.gif" fullword wide
        $v1_4 = "c:\\programdata" fullword wide
        $v1_5 = "\\tempa\\" fullword wide
        $v2_1 = "C:\\Windows\\System32\\dllhost.exe" fullword ascii
        $v2_2 = "C:\\Windows\\SysWOW64\\dllhost.exe" fullword ascii
        $v2_3 = "C:\\Users\\Public\\go" fullword ascii
        $v2_4 = ":%:*:/:>:C:H:W:\\:a:p:u:z:" fullword ascii
        $v2_5 = ": :%:*:9:>:C:R:W:\\:k:p:u:" fullword ascii
        $v2_6 = ":*:/:4:C:H:M:\\:a:f:u:z:" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of ($v1*) or 5 of ($v2*)
}
