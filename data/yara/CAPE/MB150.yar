rule MB150 {
    meta:
        author = "ditekSHen"
        description = "Detects MB150 Go ransomware"
        cape_type = "MB150 Payload"
    strings:
        $x1 = /main\.evade_(clicks_count|cpu_count|disk_size|foreground_window|hostname|mac|printer|screen_size|system_memory|time_acceleration|tmp|utc)/ fullword ascii
        $x2 = /main\.sandbox_(hostname|mac_addresses)/ fullword ascii
        $x3 = "main.drop_ransom_note" fullword ascii
        $x4 = "main.ransom_amount" fullword ascii
        $x5 = "main.create_encryption_key" fullword ascii
        $x6 = "main.encrypt" fullword ascii
        $x7 = "main.encrypt_encryption_key" fullword ascii
        $x8 = "main.encrypt_file" fullword ascii
        $x9 = "main.ext_blacklist" fullword ascii
        $mac1 = "00:03:FF00:05:6900:0C:2900:16:3E00:1C:1400:1C:4200:50:56" ascii nocase
        $mac2 = "00-03-FF00-05-6900-0C-2900-16-3E00-1C-1400-1C-4200-50-56" ascii nocase
        $mac3 = "0003FF000569000C2900163E001C14001C42005056" ascii nocase
        $go = "Go build ID:" ascii
        $s1 = "main.MB150" ascii
        $s2 = "http://1.1.1.1" ascii
        $s3 = "your personnal ID" ascii
        $s4 = "ransom amount" ascii
        $s5 = "binance.com" ascii
        $s6 = "getmonero.org" ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($x*) or ($go and 4 of ($s*)) or (1 of ($mac*) and (2 of ($x*) or 3 of ($s*))))
}
