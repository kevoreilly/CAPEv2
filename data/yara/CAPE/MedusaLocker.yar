rule MedusaLocker {
    meta:
        author = "ditekshen"
        description = "Detects MedusaLocker ransomware"
        cape_type = "MedusaLocker Payload"
    strings:
        $x1 = "\\MedusaLockerInfo\\MedusaLockerProject\\MedusaLocker\\Release\\MedusaLocker.pdb" ascii
        $x2 = "SOFTWARE\\Medusa" wide
        $x3 = "=?utf-8?B?0RFQctTF0YDQcNC60IXQvdC+IEludGVybmV0IED4cGxvseVyIDEz?=" ascii
        $s1 = "Recovery_Instructions.mht" fullword wide
        $s2 = "README_LOCK.TXT" fullword wide
        $s3 = "C:\\Users\\Public\\Desktop" wide
        $s4 = "[LOCKER] " wide
        $s5 = "TmV3LUl0ZW0gJ2" ascii
        $s6 = "<HEAD>=20" ascii
        $s7 = "LIST OF ENCRYPTED FILES" ascii
        $s8 = "KEY.FILE" ascii
        $cmd1 = { 2f 00 63 00 20 00 64 00 65 00 6c 00 20 00 00 00 20 00 3e 00 3e 00 20 00 4e 00 55 00 4c 00 }
        $cmd2 = "vssadmin.exe delete" wide nocase
        $cmd3 = "bcdedit.exe /set {default}" wide
        $cmd4 = "wbadmin delete systemstatebackup" wide nocase
        $mut1 = "{8761ABBD-7F85-42EE-B272-A76179687C63}" fullword wide
        $mut2 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" fullword wide
        $mut3 = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" fullword wide
        $ext1 = { 2e 00 52 00 65 00 61 00 64 00 49 00 6e 00 73 00
                  74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00
                  73 00 00 00 00 00 00 00 2e 00 6b 00 65 00 76 00
                  65 00 72 00 73 00 65 00 6e }
        $ext2 = ".exe,.dll,.sys,.ini,.lnk,.rdp,.encrypted" fullword ascii
    condition:
      uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and (4 of ($s*) or 1 of ($mut*))) or 6 of ($s*) or (1 of ($mut*) and 2 of ($cmd*)) or (1 of ($ext*) and 5 of them))
}
