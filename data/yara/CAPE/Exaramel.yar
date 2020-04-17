rule Exaramel {
    meta:
        author = "ditekshen"
        description = "Exaramel backdoor payload"
        cape_type = "Exaramel payload"
    strings:
        // Linux payload
        $s1 = "vendor/golang_org/x/crypto/" ascii
        $s2 = "vendor/golang_org/x/net/http2" ascii
        $s3 = "vendor/golang_org/x/text/unicode" ascii
        $s4 = "vendor/golang_org/x/text/transform" ascii
        $s5 = "config.json" ascii
        $cmd1 = "App.Update" ascii
        $cmd2 = "App.Delete" ascii
        $cmd3 = "App.SetProxy" ascii
        $cmd4 = "App.SetServer" ascii
        $cmd5 = "App.SetTimeout" ascii
        $cmd6 = "IO.WriteFile" ascii
        $cmd7 = "IO.ReadFile" ascii
        $cmd8 = "OS.ShellExecute" ascii
        $cmd9 = "awk 'match($0, /(upstart|systemd|sysvinit)/){ print substr($0, RSTART, RLENGTH);exit;" ascii
        // Windows payload
        $ws1 = "/commands/@slp" wide
        $ws2 = "/commands/cmd" wide
        $ws3 = "/settings/proxy/@password" wide
        $ws4 = "/settings/servers/server[@current='true']" wide
        $ws5 = "/settings/servers/server/@current[text()='true']" wide
        $ws6 = "/settings/servers/server[text()='%s']/@current" wide
        $ws7 = "/settings/servers/server[%d]" wide
        $ws8 = "/settings/storage" wide
        $ws9 = "/settings/check" wide
        $ws10 = "/settings/interval" wide
        $ws11 = "report.txt" wide
        $ws12 = "stg%02d.cab" ascii
        $ws13 = "urlmon.dll" ascii
        $ws14 = "ReportDir" ascii
    condition:
        (uint16(0) == 0x457f and (all of ($s*) and 6 of ($cmd*))) or (uint16(0) == 0x5a4d and 12 of ($ws*))
}
