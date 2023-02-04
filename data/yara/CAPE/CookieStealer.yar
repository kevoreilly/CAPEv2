rule CookieStealer {
    meta:
        author = "ditekSHen"
        description = "Detects generic cookie stealer"
        cape_type = "CookieStealer Payload"
    strings:
        $s1 = "([\\S]+?)=([^;|^\\r|^\\n]+)" fullword ascii
        $s2 = "(.+?): ([^;|^\\r|^\\n]+)" fullword ascii
        $s3 = "Set-Cookie: ([^\\r|^\\n]+)" fullword ascii
        $s4 = "cmd.exe /c taskkill /f /im chrome.exe" fullword ascii
        $s5 = "FIREFOX.EXE|Google Chrome|IEXPLORE.EXE" ascii
        $pdb1 = "F:\\facebook_svn\\trunk\\database\\Release\\DiskScan.pdb" fullword ascii
        $pdb2 = "D:\\Projects\\crxinstall\\trunk\\Release\\spoofpref.pdb" fullword ascii
        $ua1 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36" fullword ascii
        $ua2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($s*) and 1 of ($pdb*) and 1 of ($ua*)) or (all of ($ua*) and 1 of ($pdb*) and 2 of ($s*)))
}
