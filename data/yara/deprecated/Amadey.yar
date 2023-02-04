rule Amadey {
    meta:
        author = "ditekSHen"
        description = "Amadey downloader payload"
        cape_type = "Amadey Payload"
    strings:
        $s1 = "_ZZ14aGetProgramDirvE11UsersDirRes" fullword ascii
        $s2 = "_libshell32_a" ascii
        $s3 = "_ShellExecuteExA@4" ascii
        $s4 = "aGetTempDirvE10TempDirRes" ascii
        $s5 = "aGetHostNamevE7InfoBuf" ascii
        $s6 = "aCreateProcessPc" ascii
        $s7 = "aGetHostNamev" ascii
        $s8 = "aGetSelfDestinationiE22aGetSelfDestinationRes" ascii
        $s9 = "aGetSelfPathvE15aGetSelfPathRes" ascii
        $s10 = "aResolveHostPcE15aResolveHostRes" ascii
        $s11 = "aUrlMonDownloadPcS" ascii
        $s12 = "aWinSockPostPcS_S_" ascii
        $s13 = "aCreateProcessPc" ascii

        $v1 = "hii^" fullword ascii
        $v2 = "plugins/" fullword ascii
        $v3 = "ProgramData\\" fullword ascii
        $v4 = "&unit=" fullword ascii
        $v5 = "runas" fullword ascii wide
        $v6 = "Microsoft Internet Explorer" fullword wide
        $v7 = "stoi argument" ascii

        $av1 = "AVAST Software" fullword ascii
        $av2 = "Avira" fullword ascii
        $av3 = "Kaspersky Lab" fullword ascii
        $av4 = "ESET" fullword ascii
        $av5 = "Panda Security" fullword ascii
        $av6 = "Doctor Web" fullword ascii
        $av7 = "360TotalSecurity" fullword ascii
        $av8 = "Bitdefender" fullword ascii
        $av9 = "Norton" fullword ascii
        $av10 = "Sophos" fullword ascii
        $av11 = "Comodo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (6 of ($v*) and 2 of ($av*)))
}
