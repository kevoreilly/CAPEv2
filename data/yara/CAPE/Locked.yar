rule Locked {
    meta:
        author = "ditekSHen"
        description = "Detects Locked ransomware"
        cape_type = "Locked Payload"
    strings:
        $x1 = "http://xxxx.onion/xxxx-xxxx-xxxx-xxxx" ascii
        $x2 = "http://pigetrzlperjreyr3fbytm27bljaq4eungv3gdq2tohnoyfrqu4bx5qd.onion" ascii
        $x3 = "dHA6Ly94eHh4Lm9uaW9uL3h4eHgteHh4eC14eHh4LXh4eHg" ascii
        $s1 = "choice /t 1 /d y /n >nul" ascii
        $s2 = ".locked" fullword ascii
        $s3 = "c:\\system volume information" fullword ascii
        $s4 = "__$$RECOVERY_README$$__.html" fullword ascii
        $s5 = "Trunc..." fullword ascii
        $s6 = /C:\\windows\\temp\\[a-z0-9A-Z]{6}\.tmp/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or all of ($s*) or (1 of ($x*) and 4 of ($s*)) or (#s6 > 1 and 4 of them))
}
