rule Snake {
    meta:
        author = "ditekSHen"
        description = "Detects Snake Keylogger"
        cape_type = "Snake Payload"
    strings:
        $id1 = "SNAKE-KEYLOGGER" fullword ascii
        $id2 = "----------------S--------N--------A--------K--------E----------------" ascii
        $s1 = "_KPPlogS" fullword ascii
        $s2 = "_Scrlogtimerrr" fullword ascii
        $s3 = "_Clpreptimerr" fullword ascii
        $s4 = "_clprEPs" fullword ascii
        $s5 = "_kLLTIm" fullword ascii
        $s6 = "_TPSSends" fullword ascii
        $s7 = "_ProHfutimer" fullword ascii
        $s8 = "GrabbedClp" fullword ascii
        $s9 = "StartKeylogger" fullword ascii
        // Snake Keylogger Stub New
        $x1 = "$%SMTPDV$" wide
        $x2 = "$#TheHashHere%&" wide
        $x3 = "%FTPDV$" wide
        $x4 = "$%TelegramDv$" wide
        $x5 = "KeyLoggerEventArgs" ascii
        $m1 = "| Snake Keylogger" ascii wide
        $m2 = /(Screenshot|Clipboard|keystroke) Logs ID/ ascii wide
        $m3 = "SnakePW" ascii wide
        $m4 = "\\SnakeKeylogger\\" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (all of ($id*) or 6 of ($s*) or (1 of ($id*) and 3 of ($s*)) or 4 of ($x*))) or (2 of ($m*))
}
