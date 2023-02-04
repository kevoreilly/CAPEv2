rule SunShuttle {
    meta:
        author = "ditekSHen"
        description = "Detects SunShuttle / GoldMax"
        cape_type = "SunShuttle Payload"
    strings:
        $s1 = "main.beaconing" fullword ascii
        $s2 = "main.clean_file" fullword ascii
        $s3 = "main.decrypt" fullword ascii
        $s4 = "main.define_internal_settings" fullword ascii
        $s5 = "main.delete_empty" fullword ascii
        $s6 = "main.encrypt" fullword ascii
        $s7 = "main.false_requesting" fullword ascii
        $s8 = "main.removeBase64Padding" fullword ascii
        $s9 = "main.resolve_command" fullword ascii
        $s10 = "main.retrieve_session_key" fullword ascii
        $s11 = "main.save_internal_settings" fullword ascii
        $s12 = "main.send_command_result" fullword ascii
        $s13 = "main.send_file_part" fullword ascii
        $s14 = "main.wget_file" fullword ascii
        $s15 = "main.write_file" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
