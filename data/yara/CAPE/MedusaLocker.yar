rule MedusaLocker {
    meta:
        author = "ditekshen"
        description = "MedusaLocker Ransomware Payload"
        cape_type = "MedusaLocker Payload"
    strings:
        $s1 = "\\MedusaLockerInfo\\MedusaLockerProject\\MedusaLocker\\Release\\MedusaLocker.pdb" ascii
        $s2 = "SOFTWARE\\Medusa" wide
        $s3 = "{8761ABBD-7F85-42EE-B272-A76179687C63}" fullword wide
        $s4 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" fullword wide
        $s5 = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" fullword wide
        $s6 = "vssadmin.exe delete" wide nocase
        $s7 = "bcdedit.exe /set {default}" wide
        $s8 = "wbadmin delete systemstatebackup" wide nocase
        $s9 = ".exe,.dll,.sys,.ini,.lnk,.rdp,.encrypted" fullword ascii
        $s10 = "[LOCKER] " wide
    condition:
      uint16(0) == 0x5a4d and 6 of them
}
