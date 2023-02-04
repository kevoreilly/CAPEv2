rule NWorm {
    meta:
        author = "ditekSHen"
        description = "Detects NWorm/N-W0rm payload"
        cape_type = "NWorm Payload"
    strings:
        $id1 = "N-W0rm" ascii
        $id2 = "N_W0rm" ascii
        $x1 = "pongPing" fullword wide
        $x2 = "|NW|" fullword wide
        $s1 = "runFile" fullword wide
        $s2 = "runUrl" fullword wide
        $s3 = "killer" fullword wide
        $s4 = "powershell" fullword wide
        $s5 = "wscript.exe" fullword wide
        $s6 = "ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -File \"" fullword wide
        $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36" fullword wide
        $s8 = "Start-Sleep -Seconds 1.5; Remove-Item -Path '" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($id*) and (1 of ($x*) or 3 of ($s*))) or (all of ($x*) and 2 of ($s*)) or 7 of ($s*) or 10 of them)
}
