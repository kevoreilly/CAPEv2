rule LegionLocker {
     meta:
        author = "ditekSHen"
        description = "Detects LegionLocker ransomware"
        cape_type = "LegionLocker Payload"
    strings:
        $m1 = "+Do not run task manager, powershell, cmd etc." ascii wide
        $m2 = "3 hours your files will be deleted." ascii wide
        $m3 = "files have been encrypted by Legion Locker" ascii wide
        $s1 = "passwordBytes" fullword ascii
        $s2 = "_start_enc_" ascii
        $s3 = "_del_desktop_" ascii
        $s4 = "Processhacker" wide
        $s5 = "/k color 47 && del /f /s /q %userprofile%\\" wide
        $s6 = "Submit code" fullword wide
        $pdb1 = "\\obj\\Debug\\LegionLocker.pdb" ascii
        $pdb2 = "\\obj\\Release\\LegionLocker.pdb" ascii
    condition:
      uint16(0) == 0x5a4d and (1 of ($m*) or 1 of ($pdb*) or 4 of ($s*))
}
