rule XWorm {
    meta:
        author = "ditekSHen"
        description = "Detects XWorm"
        cape_type = "XWorm Payload"
    strings:
        $x1 = "XWorm " wide nocase
        $x2 = /XWorm\s(V|v)\d+\.\d+/ fullword wide
        $s1 = "RunBotKiller" fullword wide
        $s2 = "XKlog.txt" fullword wide
        $s3 = /(shell|reg)fuc/ fullword wide
        $s4 = "closeshell" fullword ascii
        $s5 = { 62 00 79 00 70 00 73 00 73 00 00 ?? 63 00 61 00 6c 00 6c 00 75 00 61 00 63 00 00 ?? 73 00 63 00 }
        $s6 = { 44 00 44 00 6f 00 73 00 54 00 00 ?? 43 00 69 00 6c 00 70 00 70 00 65 00 72 00 00 ?? 50 00 45 00 }
        $s7 = { 69 00 6e 00 6a 00 52 00 75 00 6e 00 00 ?? 73 00 74 00 61 00 72 00 74 00 75 00 73 00 62 }
        $s8 = { 48 6f 73 74 00 50 6f 72 74 00 75 70 6c 6f 61 64 65 72 00 6e 61 6d 65 65 65 00 4b 45 59 00 53 50 4c 00 4d 75 74 65 78 78 00 }
        $v2_1 = "PING!" fullword wide
        $v2_2 = "Urlhide" fullword wide
        $v2_3 = /PC(Restart|Shutdown)/ fullword wide
        $v2_4 = /(Start|Stop)(DDos|Report)/ fullword wide
        $v2_5 = /Offline(Get|Keylogger)/ wide
        $v2_6 = "injRun" fullword wide
        $v2_7 = "Xchat" fullword wide
        $v2_8 = "UACFunc" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and (3 of ($s*) or 3 of ($v2*))) or 6 of them)
}

rule xworm_kingrat {
    meta:
        author = "jeFF0Falltrades"
        cape_type = "XWorm payload"
    strings:
        $str_xworm = "xworm" wide ascii nocase
        $str_xwormmm = "Xwormmm" wide ascii
        $str_xclient = "XClient" wide ascii
        $str_default_log = "\\Log.tmp" wide ascii
        $str_create_proc = "/create /f /RL HIGHEST /sc minute /mo 1 /t" wide ascii 
        $str_ddos_start = "StartDDos" wide ascii 
        $str_ddos_stop = "StopDDos" wide ascii
        $str_timeout = "timeout 3 > NUL" wide ascii
        $byte_md5_hash = { 7e [3] 04 28 [3] 06 6f }
        $patt_config = { 72 [3] 70 80 [3] 04 }
    condition:
        5 of them and #patt_config >= 7
 }
