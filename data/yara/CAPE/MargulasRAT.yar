rule MargulasRAT {
    meta:
        author = "ditekSHen"
        description = "Detects MargulasRAT"
        cape_type = "MargulasRAT Payload"
    strings:
        $pdb1 = "G:\\VP-S-Fin\\memory\\" ascii
        $pdb2 = "G:\\VP-S-Fin\\Margulas\\" ascii
        $pdb3 = "G:\\VP-S-Fin\\remote" ascii
        $pdb4 = "G:\\VP-S-Fin\\" ascii
        $s1 = "/C choice /C Y /N /D Y /T 1 & Del " fullword wide
        $s2 = "strToHash" fullword ascii
        $s3 = "\\socking" fullword wide
        $s4 = "\\wininets" fullword wide
        $s5 = "ClientSocket" fullword ascii
        $s6 = "new Stream()" fullword wide
        $s7 = "CipherText" fullword ascii
        $s8 = "WriteAllBytes" fullword ascii
        $s9 = { 00 50 72 6f 63 65 73 73 00 45 78 69 73 74 73 00}
        $s10 = "pxR/THCwdLuruMmw8wB8xAUvbno1yPGBTOV9IoOkAp/n7+paQm74pkzlfSKDpAKfTOV9IoOkAp9M5X0ig6QCn0zlfSKDpAKfTOV9IoOkAp" wide
        $c1 = "149.248.52.61" wide
        $c2 = "://vpn.nic.in" wide
        $c3 = "://www.mod.gov.in/dod/sites/default/files/" wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($pdb*) and (1 of ($c*) or 3 of ($s*))) or (1 of ($c*) and 3 of ($s*)) or (6 of ($s*)))
}
