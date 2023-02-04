rule CoinMiningBot {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining bot"
        cape_type = "CoinMiningBot Payload"
    strings:
        $s1 = "FullScreenDetect" fullword ascii
        $s2 = "GetChildProcesses" fullword ascii
        $s3 = "HideBotPath" fullword ascii
        $s4 = "Inject" fullword ascii
        $s5 = "DownloadFile" fullword ascii
        $s6 = "/Data/GetUpdateInfo" wide
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
