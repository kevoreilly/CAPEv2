import "pe"

rule RedLineDropperAHK {
    meta:
        author = "ditekshen"
        description = "RedLine infostealer payload"
        cape_type = "RedLine Payload"
    strings:
        $s1 = ".SetRequestHeader(\"User-Agent\",\" ( \" OSName \" | \" bit \" | \" CPUNAme \"\"" ascii
        $s2 = ":= \" | Windows Defender\"" ascii
        $s3 = "WindowSpy.ahk" wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule RedLineDropperEXE {
    meta:
      author = "ditekSHen"
      description = "Detects executables dropping RedLine infostealer"
      cape_type = "RedLineDropperEXE Payload"
    strings:
        $s1 = "Wizutezinod togeto0Rowadufevomuki futenujilazem jic lefogatenezinor" fullword wide
        $s2 = "6Tatafamobevofaj bizafoju peyovavacoco lizine kezakajuj" fullword wide
        $s3 = "Lawuherusozeru kucu zam0Zorizeyuk lepaposupu gala kinarusot ruvasaxehuwo" fullword wide
        $s4 = "ClearEventLogW" fullword ascii
        $s5 = "ProductionVersion" fullword wide
        $s6 = "Vasuko)Yugenizugilobo toxocivoriye yexozoyohuzeb" wide
        $s7 = "Yikezevavuzus gucajanesan#Rolapucededoxu xewulep fuwehofiwifi" wide
    condition:
        uint16(0) == 0x5a4d and (pe.exports("_fgeek@8") and 2 of them) or
        (
            2 of them and
            for any i in (0 .. pe.number_of_sections) : (
                (
                    pe.sections[i].name == ".rig"
                )
            )
        )
}

rule RedLine {
    meta:
        author = "ditekSHen"
        description = "Detects RedLine infostealer"
        cape_type = "RedLine Payload"
    strings:
        $s1 = { 23 00 2b 00 33 00 3b 00 43 00 53 00 63 00 73 00 }
        $s2 = { 68 10 84 2d 2c 71 ea 7e 2c 71 ea 7e 2c 71 ea 7e
                32 23 7f 7e 3f 71 ea 7e 0b b7 91 7e 2b 71 ea 7e
                2c 71 eb 7e 5c 71 ea 7e 32 23 6e 7e 1c 71 ea 7e
                32 23 69 7e a2 71 ea 7e 32 23 7b 7e 2d 71 ea 7e }
        $s3 = { 83 ec 38 53 b0 ?? 88 44 24 2b 88 44 24 2f b0 ??
                88 44 24 30 88 44 24 31 88 44 24 33 55 56 8b f1
                b8 0c 00 fe ff 2b c6 89 44 24 14 b8 0d 00 fe ff
                2b c6 89 44 24 1c b8 02 00 fe ff 2b c6 89 44 24
                18 b3 32 b8 0e 00 fe ff 2b c6 88 5c 24 32 88 5c
                24 41 89 44 24 28 57 b1 ?? bb 0b 00 fe ff b8 03
                00 fe ff 2b de 2b c6 bf 00 00 fe ff b2 ?? 2b fe
                88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34
                78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6
                44 24 41 33 c6 44 24 43 ?? c6 44 24 44 74 88 54
                24 46 c6 44 24 40 ?? c6 44 24 39 62 c7 44 24 10 }
        $s4 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide
        $s5 = " delete[]" fullword ascii
        $s6 = "constructor or from DllMain." ascii

        $x1 = "RedLine.Reburn" ascii
        $x2 = "RedLine.Client." ascii
        $x3 = "hostIRemotePanel, CommandLine: " fullword wide
        $u1 = "<ParseCoinomi>" ascii
        $u2 = "<ParseBrowsers>" ascii
        $u3 = "<GrabScreenshot>" ascii
        $u4 = "UserLog" ascii nocase
        $u5 = "FingerPrintT" fullword ascii
        $u6 = "InstalledBrowserInfoT" fullword ascii
        $u7 = "RunPE" fullword ascii
        $u8 = "DownloadAndEx" fullword ascii
        $u9 = ".Data.Applications.Wallets" ascii
        $u10 = ".Data.Browsers" ascii
        $u11 = ".Models.WMI" ascii
        $u12 = "DefenderSucks" wide

        $pat1 = "(((([0-9.])\\d)+){1})" fullword wide
        $pat2 = "^(?:2131|1800|35\\\\d{3})\\\\d{11}$" fullword wide
        $pat3 = "6(?:011|5[0-9]{2})[0-9]{12}$/C" fullword wide
        $pat4 = "Telegramprofiles^(6304|6706|6709|6771)[0-9]{12,15}$" fullword wide
        $pat5 = "host_key^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" fullword wide
        $pat6 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" wide
        $pat7 = "settingsprotocol^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" wide
        $pat8 = "Opera GX4[0-9]{12}(?:[0-9]{3})?$cookies" wide
        $pat9 = "^9[0-9]{15}$Coinomi" wide
        $pat10 = "wallets^(62[0-9]{14,17})$" wide
        $pat11 = "hostpasswordUsername_value" wide
        $pat12 = "credit_cards^389[0-9]{11}$" wide
        $pat13 = "NWinordVWinpn.eWinxe*WinhostUsername_value" wide
        $pat14 = /(\/|,\s)CommandLine:/ wide
        // another variant
        $v2_1 = "ListOfProcesses" fullword ascii
        $v2_2 = /get_Scan(ned)?(Browsers|ChromeBrowsersPaths|Discord|FTP|GeckoBrowsersPaths|Screen|Steam|Telegram|VPN|Wallets)/ fullword ascii
        $v2_3 = "GetArguments" fullword ascii
        $v2_4 = "VerifyUpdate" fullword ascii
        $v2_5 = "VerifyScanRequest" fullword ascii
        $v2_6 = "GetUpdates" fullword ascii
        // yet another variant
        $v3_1 = "localhost.IUserServiceu" fullword ascii
        $v3_2 = "ParseNetworkInterfaces" fullword ascii
        $v3_3 = "ReplyAction0http://tempuri.org/IUserService/GetUsersResponse" fullword ascii
        $v3_4 = "Action(http://tempuri.org/IUserService/GetUsersT" fullword ascii
        $v3_5 = "basicCfg" fullword wide
        // more variants
        $vx4_1 = "C:\\\\Windows\\\\Microsoft.NET\\\\Framework\\\\v4.0.30319\\\\AddInProcess32.exe" fullword wide
        $v4_2 = "isWow64" fullword ascii
        $v4_3 = "base64str" fullword ascii
        $v4_4 = "stringKey" fullword ascii
        $v4_5 = "BytesToStringConverted" fullword ascii
        $v4_6 = "FromBase64" fullword ascii
        $v4_7 = "xoredString" fullword ascii
        $v4_8 = "procName" fullword ascii
        $v4_9 = "base64EncodedData" fullword ascii
        // another variant 2021-10-23
        $v5_1 = "DownloadAndExecuteUpdate" fullword ascii
        $v5_2 = "ITaskProcessor" fullword ascii
        $v5_3 = "CommandLineUpdate" fullword ascii
        $v5_4 = "DownloadUpdate" fullword ascii
        $v5_5 = "FileScanning" fullword ascii
        $v5_6 = "GetLenToPosState" fullword ascii
        $v5_7 = "RecordHeaderField" fullword ascii
        $v5_8 = "EndpointConnection" fullword ascii
        $v5_9 = "BCRYPT_KEY_LENGTHS_STRUCT" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and (all of ($s*) or 2 of ($x*) or 7 of ($u*) or 7 of ($pat*) or (1 of ($x*) and (5 of ($u*) or 2 of ($pat*))) or 5 of ($v2*) or 4 of ($v3*) or (3 of ($v2*) and (2 of ($pat*) or 2 of ($u*)) or (1 of ($vx4*) and 5 of ($v4*)) or 5 of ($v4*) or 6 of ($v5*)))) or (all of ($x*) and 4 of ($s*))
}
