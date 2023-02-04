rule Gelsemine {
    meta:
        author = "ditekSHen"
        description = "Detects Gelsemine"
        cape_type = "Gelsemine Payload"
    strings:
        $s1 = "If any of these steps fails.only pick one of the targets for configuration\"If you want to just get on with it*which also use [ " wide
        $s2 = "A make implementation+with core modules (please read NOTES.PER_L)2The per_l Text::Template (please read NOTES.PER_L)" wide
        $s3 = "NOTES.VMS (OpenVMS)!NOTES.WIN (any supported Windows)%NOTES.DJGPP (DOS platform with DJGPP)'NOTES.ANDROID (obviously Android [ND" wide
        $s4 = "A simple example would be this)which is to be understood as one of these" fullword wide
        $s5 = "bala bala bala" fullword wide
        $s6 = "echo FOO" fullword wide
        $s7 = "?_Tidy@?$basic_string@DU?$char_traits@D@std@@V" ascii
        $o1 = { eb 08 c7 44 24 34 fd ff ff ff 8b 44 24 54 8b 4c }
        $o2 = { eb 08 c7 44 24 34 fd ff ff ff 8b 44 24 54 8b 4c }
        $o3 = { 8b 76 08 2b f0 a1 34 ff 40 00 03 f0 89 35 38 ff }
        $o4 = { 83 c4 34 c3 8b 4e 20 6a 05 e8 73 10 00 00 8b 76 }
        $o5 = { 8b 44 24 44 2b d1 03 d0 8b f2 e9 14 ff ff ff 8d }
        $o6 = { 68 00 06 00 00 6a 00 e8 d3 ff ff ff a2 48 00 41 }
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (all of ($o*) and 2 of ($s*)))
}

rule Gelsenicine {
    meta:
        author = "ditekSHen"
        description = "Detects Gelsenicine"
        cape_type = "Gelsenicine Payload"
    strings:
        $s1 = "System/" fullword wide
        $s2 = "Windows/" fullword wide
        $s3 = "CommonAppData/" fullword wide
        $s5 = ".?AUEmbeddedResource@@" fullword ascii
        $ms1 = "pulse" fullword wide
        $ms2 = "mainpath" fullword wide
        $ms3 = "mainpath64" fullword wide
        $ms4 = "pluginkey" fullword wide
        $o1 = { 48 8d 54 24 68 48 8b 4c 39 10 e8 4d ff ff ff 44 }
        $o2 = { 48 8d 54 24 30 48 8b cb e8 34 f2 ff ff 84 c0 74 }
        $o3 = { 48 c7 44 24 ?? fe ff ff ff 49 8b f0 48 8b d9 ?? }
        $o4 = { 89 44 24 30 89 44 24 34 48 8b 53 08 48 85 d2 48 }
        $o5 = { ff ff ff ff 49 f7 d1 4c 23 f8 8b 43 10 48 8b e9 }
        $o6 = { 83 c4 24 85 c0 74 3c 8b 0b 8b 41 34 8b 4d 34 2b }
        $o7 = { 8b 45 34 8b 53 fc 50 8b cf 6a 04 68 00 10 00 00 }
        $o8 = { 80 74 1f 8b 4e 34 8b 54 24 18 25 ff ff 00 00 51 }
        $o9 = { eb 47 8b 4c 24 14 8b 56 34 52 8d 3c 08 8b 44 24 }
        $o10 = { 8b 44 24 0c 5d 5e 5b 83 c4 10 c3 8b 4e 34 51 57 }
        $o11 = { 6a 03 53 53 56 68 34 00 e4 74 ff 15 80 d0 e3 74 }
    condition:
        uint16(0) == 0x5a4d and ((all of ($s*) and (3 of ($ms*) or 4 of ($o*))) or (all of ($ms*) and 2 of ($s*) and 3 of ($o*)))
}

rule Gelsevirine {
    meta:
        author = "ditekSHen"
        description = "Detects Gelsevirine"
        cape_type = "Gelsevirine Payload"
    strings:
        $s1 = /64loadpath(xp|sv|7)/ fullword wide
        $s2 = "{\"Actions\":[]}" fullword wide
        $s3 = "PlatformsChunk" fullword wide
        $s4 = "CurrentPluginCategory" fullword wide
        $s5 = "CurrentOperationPlatform" fullword wide
        $s6 = "PersistencePlugins" fullword wide
        $s7 = "memory_library_file" fullword wide
        $s8 = "LoadPluginBP" fullword ascii
        $s9 = "GetOperationBasicInformation" fullword ascii
        $s10 = "commonappdata/Intel/Runtime" wide
        $s11 = "cfsst x64" fullword wide
        $s12 = "ForkOperation" fullword ascii
        $c1 = "domain.dns04.com:8080;domain.dns04.com:443;acro.ns1.name:80;acro.ns1.name:1863;" wide
        $c2 = "<base64 content=\"" fullword ascii
        $c3 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" fullword ascii
        $m1 = "6BDA7FEF-232F-4EA6-8FC8-24F58CD7B366" ascii wide
        $m2 = "46EBBDC3-EEDC-42D4-BA1D-D454DFCE8E42" ascii wide
        $m3 = "135054C6-8036-42C7-A97C-31F37D7728BD" ascii wide
        $m4 = "DC7FDDF7-B2F1-4B99-BE6A-AA683FF11CE6" ascii wide
        $m5 = "131C8113-E083-4C7F-BEAF-82D73B01F2C5" ascii wide
        $m6 = "4CCF506D-2F61-4C3A-B9C6-9FA47D43A3FC" ascii wide
        $m7 = "B2DC745A-66AE-4A19-B11C-AD74D46B7EE0" ascii wide
        $m8 = "6BDA7FEF-232F-4EA6-8FC8-24F58CD7B366" ascii wide
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (2 of ($c*) and 4 of ($s*)) or (5 of ($m*) and (1 of ($c*) or 3 of ($s*))))
}
