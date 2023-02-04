rule PirateStealer {
    meta:
        author = "ditekSHen"
        description = "Detects PirateStealer"
        cape_type = "PirateStealer Infostealer Payload"
    strings:
        $s1 = "PirateStealerBTW" wide
        $s2 = "%WEBHOOK_LINK%" fullword wide
        $s3 = "PirateMonsterInjector" ascii wide
        $s4 = "DiscordProcesses" fullword ascii
        $s5 = "GetDiscords" fullword ascii
        $s6 = { 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 00 47
               65 74 46 6f 6c 64 65 72 50 61 74 68 00 57 65 62
               68 6f 6f 6b 00 4b 69 6c 6c 00 50 72 6f 67 72 61
               6d 00 53 79 73 74 65 6d 00 4d 61 69 6e 00 }
    condition:
        uint16(0) == 0x5a4d and 3 of them
}
