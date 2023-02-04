rule Tofsee {
    meta:
        author = "ditekSHen"
        description = "Detects Tofsee"
        cape_type = "Tofsee Payload"
    strings:
        $s1 = "n%systemroot%\\system32\\cmd.exe" fullword wide
        $s2 = "loader_id" fullword ascii
        $s3 = "start_srv" fullword ascii
        $s4 = "lid_file_upd" fullword ascii
        $s5 = "localcfg" fullword ascii
        $s6 = "Incorrect respons" fullword ascii
        $s7 = "mx connect error" fullword ascii
        $s8 = "Error sending command (sent = %d/%d)" fullword ascii
        $s9 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
