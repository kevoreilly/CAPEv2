rule Origin {
    meta:
        author = "kevoreilly"
        description = "Origin Logger payload"
        cape_type = "Origin Payload"
        hash = "ee8a244c904756bdc3987fefc844596774437bcc50d4022ddcc94e957cab6a11"
    strings:
        $s1 = "set_RequestPluginName" fullword ascii
        $s2 = "set_IsCreated" fullword ascii
        $s3 = "set_AllowAutoRedirect" fullword ascii
        $s4 = "set_Antivirus" fullword ascii
        $s5 = "set_MaximumAutomaticRedirections" fullword ascii
        $s6 = "set_ClientId" fullword ascii
        $s7 = "set_SysInfo" fullword ascii
        $s8 = "set_ServerCertificateValidationCallback" fullword ascii
        $s9 = "set_CommandType" fullword ascii
        $s10 = "set_TenantId" fullword ascii
        $s11 = "set_KeepAlive" fullword ascii

        $c1 = {03 16 32 0B 03 2C 08 02 6F 49 00 00 0A 2D 06}
        $c2 = {20 F0 0F 00 00 28 ?? 00 00 0A 7E ?? 00 00 04 2D 11 14 FE}
        $c3 = {06 20 20 4E 00 00 6F ?? 00 00 0A 06 17 6F ?? 00 00 0A 06 1F 32 6F}
        $c4 = {20 00 01 00 00 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0A 72 ?? 05 00 70 28 ?? 00 00 0A 0A 12 00 28}

        $m1 = "OriginBotnet" ascii
        $m2 = "UpdateBotRequest" ascii
        $m3 = "<Deserialize>b__0" ascii
    condition:
        (uint16(0) == 0x5a4d and ((6 of ($s*) and 2 of ($c*)))) or (2 of ($m*))
}
