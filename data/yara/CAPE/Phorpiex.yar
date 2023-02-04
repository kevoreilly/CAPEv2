rule Phorpiex {
    meta:
      author = "ditekSHen"
      description = "Detects Phorpiex variants"
      cape_type = "Phorpiex Payload"
    strings:
       $s1 = "ShEllExECutE=__\\DriveMgr.exe" fullword wide nocase
       $s2 = "/c start __ & __\\DriveMgr.exe & exit" fullword wide nocase
       $s3 = "%s\\autorun.inf" fullword wide
       $s4 = "svchost." wide
       $s5 = "%ls\\%d%d" wide
       $s6 = "bitcoincash:" ascii
       $s7 = "%ls:*:Enabled:%ls" fullword wide
       $s8 = "%s\\%s\\DriveMgr.exe" fullword wide
       $s9 = "api.wipmania.com" ascii
       $v1_1 = "%appdata%" fullword wide
       $v1_2 = "(iPhone;" ascii
       $v1_3 = "/tst.php" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or all of ($v1*))
}
