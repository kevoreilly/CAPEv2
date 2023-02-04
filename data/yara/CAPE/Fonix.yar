rule Fonix {
    meta:
        author = "ditekSHen"
        description = "Detects Fonix ransomware"
        cape_type = "Fonix Payload"
    strings:
        $s1 = "dontcryptanyway" fullword wide
        $s2 = "Cpriv.key" ascii wide
        $s3 = "Cpub.key" ascii wide
        $s4 = "NetShareEnum() failed!Error: % ld" fullword wide
        $s5 = "<div class='title'> Attention!</div><ul><li><u><b>DO NOT</b> pay" wide
        $s6 = "Encryption Completed !!!" fullword wide
        $s7 = "kill process" fullword ascii
        $s8 = "Copy SystemID C:\\ProgramData\\SystemID" ascii
        $id1 = "].FONIX" fullword wide
        $id2 = "xinofconfig.txt" fullword ascii wide
        $id3 = "XINOF4MUTEX" wide
        $id4 = ":\\Fonix\\cryptoPP\\" ascii
        $id5 = "schtasks /CREATE /SC ONLOGON /TN fonix" ascii
        $id6 = "Ransomware\\Fonix" ascii
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or 3 of ($id*) or (1 of ($id*) and 3 of ($s*)))
}
