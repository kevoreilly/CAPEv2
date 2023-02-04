rule Crown {
     meta:
        author = "ditekSHen"
        description = "Detects Crown Tech Support Scam"
        cape_type = "Crown Tech Support Scam Payload"
    strings:
        $d1 = "//prodownload.live" ascii
        $c1 = "&uid=" ascii
        $c2 = "&ver=" ascii
        $c3 = "&mcid=" ascii
        $c4 = ".php?uid=" ascii
        $c5 = ".php?ip=" ascii
        $s1 = "Operating System Support ID:" ascii
        $s2 = "taskkill /IM explorer.exe -f" ascii nocase
        $s3 = "/C taskkill /IM Taskmgr.exe -f" ascii nocase
        $s4 = "FastSuport" fullword ascii
        $s5 = "Support Override!" fullword wide
        $s6 = "Support Assistance Override Activated!" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($c*) or 4 of ($s*) or (1 of ($d*) and (3 of ($c*) or 2 of ($s*))))
}
