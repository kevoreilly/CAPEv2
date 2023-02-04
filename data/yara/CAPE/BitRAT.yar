rule BitRAT {
    meta:
        author = "ditekSHen"
        description = "Detects BitRAT RAT"
        cape_type = "BitRAT Payload"
    strings:
        $s1 = "\\plg\\" fullword ascii
        $s2 = "klgoff_del" fullword ascii
        $s3 = "files_delete" ascii
        $s4 = "files_zip_start" fullword ascii
        $s5 = "files_exec" fullword ascii
        $s6 = "drives_get" fullword ascii
        $s7 = "srv_list" fullword ascii
        $s8 = "con_list" fullword ascii
        $s9 = "ddos_stop" fullword ascii
        $s10 = "socks5_srv_start" fullword ascii
        $s11 = "/getUpdates?offset=" fullword ascii
        $s12 = "Action: /dlex" fullword ascii
        $s13 = "Action: /clsbrw" fullword ascii
        $s14 = "Action: /usb" fullword ascii
        $s15 = "/klg" fullword ascii
        $s16 = "klg|" fullword ascii
        $s17 = "Slowloris" fullword ascii
        $s18 = "Bot ID:" ascii
        $t1 = "<sz>N/A</sz>" fullword ascii
        $t2 = "<silent>N/A</silent>" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (4 of ($s*) and 1 of ($t*)))
}
