rule BlackshadesRAT {
    meta:
        author = "ditekshen"
        description = "BlackshadesRAT POS payload"
        cape_type = "BlackshadesRAT payload"
    strings:
        $s1 = "bhookpl.dll" fullword wide
        $s2 = "drvloadn.dll" fullword wide
        $s3 = "drvloadx.dll" fullword wide
        $s4 = "SPY_NET_RATMUTEX" fullword wide
        $s5 = "\\dump.txt" fullword wide
        $s6 = "AUTHLOADERDEFAULT" fullword wide
        $pdb = "*\\AC:\\Users\\Admin\\Desktop_old\\Blackshades project\\bs_bot\\bots\\bot\\bs_bot.vbp" fullword wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or ($pdb and 2 of ($s*)))
}
