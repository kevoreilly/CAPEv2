rule InfinityLock {
    meta:
        author = "ditekSHen"
        description = "Detects InfinityLock ransomware"
        cape_type = "InfinityLock Payload"
    strings:
        $s1 = "_Encrypted$" fullword ascii
        $s2 = "PublicKeyToken=" fullword ascii nocase
        $s3 = "GenerateHWID" fullword ascii
        $s4 = "CreateKey" fullword ascii
        $d1 = "ProgrammFiles" fullword ascii
        $d2 = "OneDrive" fullword ascii
        $d3 = "ProgrammsX86" fullword ascii
        $d4 = "UserDirs" fullword ascii
        $d5 = "B_Drive" fullword ascii
        $pdb1 = "F:\\DESKTOP!\\ChkDsk\\ChkDsk\\obj\\" ascii
        $pdb2 = "\\ChkDsk\\obj\\Debug\\PremiereCrack.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($s*) and 1 of ($d*)) or (4 of ($d*) and 2 of ($s*)) or (any of ($pdb*) and 1 of ($s*) and 1 of ($d*)))
}
