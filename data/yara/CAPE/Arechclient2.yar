rule Arechclient2 {
    meta:
        author = "ditekSHen"
        description = "Detects Arechclient2 RAT"
        cape_type = "Arechclient2 Payload"
    strings:
        $s1 = "\\Google\\Chrome\\User Data\\copiedProf\"" wide
        $s2 = "\",\"BotName\":\"" wide
        $s3 = "\",\"BotOS\":\"" wide
        $s4 = "\",\"URLData\":\"" wide
        $s5 = "{\"Type\":\"ConnectionType\",\"ConnectionType\":\"Client\",\"SessionID\":\"" wide
        $s6 = "{\"Type\":\"TestURLDump\",\"SessionID\":\"" wide
        $s7 = "<ReceiveParticipantList>" ascii
        $s8 = "<potocSkr>" ascii
        $s9 = "fuck_sd" fullword ascii
        $s10 = "HandleBotKiller" fullword ascii
        $s11 = "RunBotKiller" fullword ascii
        $s12 = "ConnectToServer" fullword ascii
        $s13 = "KillBrowsers" fullword ascii
        $s14 = "keybd_event" fullword ascii
        $s15 = "FuckCodeImg" fullword ascii
        $v1_1 = "grabber@" fullword ascii
        $v1_2 = "<BrowserProfile>k__" ascii
        $v1_3 = "<SystemHardwares>k__" ascii
        $v1_4 = "<geoplugin_request>k__" ascii
        $v1_5 = "<ScannedWallets>k__" ascii
        $v1_6 = "<DicrFiles>k__" ascii
        $v1_7 = "<MessageClientFiles>k__" ascii
        $v1_8 = /<Scan(Browsers|Wallets|Screen|VPN)>k__BackingField/ fullword ascii
        $v1_9 = "displayName[AString-ZaString-z\\d]{2String4}\\.[String\\w-]{String6}\\.[\\wString-]{2String7}Local Extension Settingshost" wide
        $v1_10 = "\\sitemanager.xml MB or SELECT * FROM Cookiesconfig" wide
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or 7 of ($v1*) or (6 of ($v1*) and 1 of ($s*)))
}
