rule MoDiRAT {
    meta:
        author = "ditekshen"
        description = "MoDiRAT payload"
        cape_type = "MoDiRAT payload"
    strings:
        $s1 = "add_Connected" fullword ascii
        $s2 = "Statconnected" fullword ascii
        $s3 = "StartConnect" fullword ascii
        $s4 = "TelegramTitleDetect" fullword ascii
        $s5 = "StartTitleTelegram" fullword ascii
        $s6 = "Check_titles" fullword ascii
        $s7 = "\\MoDi RAT V" ascii
        $s8 = "IsBuzy" fullword ascii
        $s9 = "Recording_Time" fullword wide
    condition:
        (uint16(0) == 0x5a4d and 7 of them) or all of them
}
