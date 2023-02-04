rule RevCodeRAT {
    meta:
        author = "ditekSHen"
        description = "RevCodeRAT  infostealer payload"
        cape_type = "RevCodeRAT  Payload"
    strings:
        $x1 = "rev-novm.dat" fullword wide
        $x2 = "WebMonitor-" fullword wide
        $x3 = "WebMonitor Client" fullword wide
        $x4 = "Launch WebMonitor" fullword wide

        $s1 = "KEYLOG_DEL" fullword ascii
        $s2 = "KEYLOG_STREAM_START" fullword ascii
        $s3 = "send_keylog_del" fullword ascii
        $s4 = "send_keylog_stream_" ascii
        $s5 = "send_shell_exec" fullword ascii
        $s6 = "send_file_download_exec" fullword ascii
        $s7 = "send_pdg_exec" fullword ascii
        $s8 = "send_app_cmd_upd" fullword ascii
        $s9 = "send_webcamstream_start" fullword ascii
        $s10 = "send_screenstream_start" fullword ascii
        $s11 = "send_clipboard_get" fullword ascii
        $s12 = "send_pdg_rev_proxy_stop" fullword ascii
        $s13 = "send_shell_stop" fullword ascii
        $s14 = "send_wnd_cmd" fullword ascii
        $s15 = "SCREEN_STREAM_LEGACY(): Started..." fullword ascii
        $s16 = "SYSTEM_INFORMATION(): Failed! (Error:" fullword ascii
        $s17 = "TARGET_HOST_UPDATE(): Sync successful!" fullword ascii
        $s18 = "PLUGIN_PROCESS_REVERSE_PROXY: Plugin" ascii
        $s19 = "PLUGIN_PROCESS: Plugin" ascii
        $s20 = "PLUGIN_EXEC: Plugin" ascii
        $s21 = "PLUGIN_PROCESS_SCREEN_STREAM: Plugin" ascii

        $cnc1 = "?task_id=" fullword ascii
        $cnc2 = "&operation=" fullword ascii
        $cnc3 = "&filesize=" fullword ascii
        $cnc4 = "pos=" fullword ascii
        $cnc5 = "&mode=" fullword ascii
        $cnc6 = "&cmp=1" fullword ascii
        $cnc7 = "&cmp=0" fullword ascii
        $cnc8 = "&enc=1" fullword ascii
        $cnc9 = "&enc=0" fullword ascii
        $cnc10 = "&user=" fullword ascii
        $cnc11 = "&uid=" fullword ascii
        $cnc12 = "&key=" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or all of ($cnc*) or 8 of ($s*) or (1 of ($x*) and 6 of ($s*)) or (6 of ($cnc*) and 6 of ($s*)))
}
