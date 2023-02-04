rule JSSLoader {
    meta:
        author = "ditekSHen"
        description = "Detects JSSLoader RAT/backdoor"
        cape_type = "JSSLoader RAT Payload"
    strings:
        $cmd1 = "Cmd_UPDATE" fullword ascii
        $cmd2 = "Cmd_IDLE" fullword ascii
        $cmd3 = "Cmd_EXE" fullword ascii
        $cmd4 = "Cmd_VBS" fullword ascii
        $cmd5 = "Cmd_JS" fullword ascii
        $cmd6 = "Cmd_PWS" fullword ascii
        $cmd7 = "Cmd_RAT" fullword ascii
        $cmd8 = "Cmd_UNINST" fullword ascii
        $cmd9 = "Cmd_RunDll" fullword ascii
        $s1 = "ANSWER_OK" fullword ascii
        $s2 = "GatherDFiles" ascii
        $s3 = "CommandCd" fullword ascii
        $s4 = "URL_GetCmd" fullword ascii
        $s5 = "\"host\": \"{0}\", \"domain\": \"{1}\", \"user\": \"{2}\"" wide
        $s6 = "pc_dns_host_name" wide
        $s7 = "\"adinfo\": { \"adinformation\":" wide
        $e1 = "//e:vbscript" wide
        $e2 = "//e:jscript" wide
        $e3 = "/c rundll32.exe" wide
        $e4 = "/C powershell" wide
        $e5 = "C:\\Windows\\System32\\cmd.exe" wide
        $e6 = "echo del /f" wide
        $e7 = "AT.U() {0}. format" wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($cmd*) or 5 of ($s*) or all of ($e*) or 7 of them)
}
