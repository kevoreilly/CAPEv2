rule JesterStealer {
    meta:
        author = "ditekSHen"
        description = "Detects JesterStealer"
        cape_type = "JesterStealer Payload"
    strings:
        $s1 = /\[(Credman|Networks|Screenshot|Vault)\]\s\{0\}/ fullword wide
        $s3 = "encoding=\"base64\"" fullword wide
        $s4 = "/json/list" fullword wide
        $s5 = "/L1ghtM4n/TorProxy/" ascii wide
        $s6 = "<EnumerateCredentials>" ascii
        $s7 = "<EnumerateBrowsers>" ascii
        $s8 = "<PerformSelfDestruct>" ascii
        $s9 = "<get_GrabberCount>" ascii
        $s10 = "AnalyzeData" fullword ascii
        $s11 = "CheckCard" fullword ascii
        $s12 = "CreateGrabberZipPath" fullword ascii
        $s13 = "Jester" fullword ascii
        $s14 = /Stealer\.(Recovery|Grabber|Investigation)\./ ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
