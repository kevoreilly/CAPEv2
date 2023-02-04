rule BioPassDropper {
    meta:
        author = "ditekSHen"
        description = "Detects Go BioPass dropper"
        cape_type = "BioPassDropper Payload"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "main.NetWorkStatus" ascii
        $s2 = "main.NoErrorRunFunction" ascii
        $s3 = "main.FileExist" ascii
        $s4 = "main.execute" ascii
        $s5 = "main.PsGenerator" ascii
        $s6 = "main.downFile" ascii
        $s7 = "main.Unzip" ascii
        $url1 = "https://flashdownloadserver.oss-cn-hongkong.aliyuncs.com/res/" ascii
        $x1 = "SCHTASKS /Run /TN SYSTEM_CDAEMON" ascii
        $x2 = "SCHTASKS /Run /TN SYSTEM_SETTINGS" ascii
        $x3 = "SCHTASKS /Run /TN SYSTEM_TEST && SCHTASKS /DELETE /F /TN SYSTEM_TEST" ascii
        $x4 = ".exe /install /quiet /norestart" ascii
        $x5 = "exec(''import urllib.request;exec(urllib.request.urlopen(urllib.request.Request(\\''http" ascii
        $x6 = "powershell.exe -Command $" ascii
        $x7 = ".Path ='-----BEGIN RSA TESTING KEY-----" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 5 of ($x*) or (1 of ($url*) and ($go)) or 9 of them)
}
