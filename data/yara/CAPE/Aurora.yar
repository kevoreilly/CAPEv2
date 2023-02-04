rule Aurora {
    meta:
        author = "ditekshen"
        description = "Aurora Payload"
        cape_type = "Aurora payload"
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii wide
        $s2 = "#DECRYPT_MY_FILES#.txt" fullword ascii
        $s3 = "/gen.php?generate=" fullword ascii
        $s4 = "geoplugin.net/php.gp" ascii
        $s5 = "/end.php?id=" fullword ascii
        $s6 = "wotreplay" fullword ascii
        $s7 = "moneywell" fullword ascii
        $s8 = "{btc}" fullword ascii
        $s9 = ".?AV_Locimp@locale@std@@" ascii
        $s10 = ".?AV?$codecvt@DDU_Mbstatet@@@std@@" ascii
        $s11 = ".?AU_Crt_new_delete@std@@" ascii
        $pdb1 = "\\z0ddak\\Desktop\\source\\Release\\Ransom.pdb" ascii
        $pdb2 = "\\Desktop\\source\\Release\\Ransom.pdb" ascii
    condition:
         uint16(0) == 0x5a4d and ((1 of ($pdb*) and 5 of ($s*)) or (8 of them))
}
