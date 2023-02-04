rule Clop {
    meta:
        author = "ditekSHen"
        description = "Detects Clop ransomware variants"
        cape_type = "Clop Payload"
    strings:
        $x1 = "Cllp^_-" ascii
        $s2 = "temp.dat" fullword wide
        $s3 = "README_README.txt" wide
        $s4 = "BEGIN PUBLIC KEY" ascii
        $s5 = "runrun" wide
        $s6 = "wevtutil.exe" ascii
        $s7 = "%s%s.Cllp" fullword wide
        $s8 = "WinCheckDRVs" fullword wide
        $s9 = "READ_ME_!!!.TXT" wide
        $s10 = "ENDOEFEND123" wide
        $o1 = { 6a ff 56 89 9d 28 dd ff ff ff d0 a1 64 32 41 00 }
        $o2 = { 56 89 9d 28 dd ff ff ff 15 78 32 41 00 eb 07 43 }
        $o3 = { 68 ?? 34 41 00 8d 85 58 dd ff ff 50 ff d7 85 c0 }
        $o4 = { 68 d0 34 41 00 50 ff d6 8b bd 28 d5 ff ff 83 c4 }
        $o5 = { a1 64 32 41 00 43 56 89 9d 08 d5 ff ff ff d0 8b }
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($x*) and (3 of ($s*) or 4 of ($o*))) or (all of ($o*) and 2 of ($s*)) or (4 of ($s*) and 4 of ($o*)))
        //uint16(0) == 0x5a4d and any of them
}
