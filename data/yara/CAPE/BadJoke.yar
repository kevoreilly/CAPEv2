rule BadJoke {
    meta:
        author = "ditekSHen"
        description = "Detects BadJoke / Witch"
        cape_type = "BadJoke / Witch Payload"
    strings:
        $s1 = "msdownld.tmp" fullword ascii
        $s2 = "UPDFILE%lu" fullword ascii
        $s3 = "Command.com /c %s" fullword ascii
        $s4 = "launch.cmd" fullword ascii
        $s5 = "virus.vbs" fullword ascii
        $s6 = "virus.py" fullword ascii
        $m1 = "Message from Google Virus" ascii
        $m2 = "you cannot get rid of this virus" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($m*) or all of ($s*) or (1 of ($m*) and 2 of ($s*)))
}
