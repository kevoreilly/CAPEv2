rule ButeRAT {
    meta:
        author = "ditekSHen"
        description = "Detects ButeRAT"
        cape_type = "ButeRAT Payload"
    strings:
        $x1 = "TVqQAAMAA" ascii
        $s1 = "ipinfo.io/geo" wide
        $s2 = "/index.php" wide
        $s3 = "Copy-Item -Path" wide
        $s4 = ";Start-Process" wide
        $s5 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" wide
        $s6 = "LOCALAPPDATA" fullword wide
        $s7 = "passwords.json" wide
        $s8 = "Scripting.FileSystemObject" fullword wide
        $z1 = /(edge|chrome|opera|exodus|jaxx|atomic|coinomi)\.zip/ ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) or 1 of ($z*)) and (4 of ($s*)) or (6 of ($s*)) or (#z1 > 4 and 2 of them))
}
