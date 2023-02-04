rule PillowMint {
    meta:
        author = "ditekshen"
        description = "PillowMint POS payload"
        cape_type = "PillowMint payload"
    strings:
        $s1 = "system32\\sysvols\\" ascii nocase
        $s2 = "Sysnative\\sysvols\\" ascii nocase
        $s3 = "critical.log" fullword ascii
        $s4 = "log.log" fullword ascii
        $s5 = "commands.txt" fullword ascii
        $s6 = "_EV0LuTi0N_" ascii
        $s7 = /(file|reg)\scmd:/ fullword ascii
        $s8 = "dumper_nologs_" ascii
        $s9 = "ReflectiveLoader" ascii
    condition:
       uint16(0) == 0x5a4d and 6 of them
}
