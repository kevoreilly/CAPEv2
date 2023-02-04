rule JennLog {
    meta:
        author = "ditekSHen"
        description = "Detects JennLog loader"
        cape_type = "JennLog Loader Payload"
    strings:
        $x1 = "%windir%\\system32\\rundll32.exe advapi32.dll,ProcessIdleTasks" fullword wide
        $x2 = "https://fkpageintheworld342.com" fullword wide
        $s1 = "ExecuteInstalledNodeAndDelete" fullword ascii
        $s2 = "ProcessExsist" fullword ascii
        $s3 = "helloworld.Certificate.txt" fullword wide
        $s4 = "ASCII85 encoded data should begin with '" fullword wide
        $s5 = "] WinRE config file path: C:\\" ascii
        $s6 = "] Parameters: configWinDir: NULL" ascii
        $s7 = "] Update enhanced config info is enabled." ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*)) or 5 of ($s*) or (all of ($x*) and 2 of ($s*)))
}
