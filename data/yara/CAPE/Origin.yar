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
        $s5 = "set_Timeout" fullword ascii
        $s6 = "set_Method" fullword ascii
        $s7 = "set_Username" fullword ascii
        $s8 = "set_ContentLength" fullword ascii
        $s9 = "set_Nation" fullword ascii
        $s10 = "set_MaximumAutomaticRedirections" fullword ascii
        $s11 = "set_ClientId" fullword ascii
        $s12 = "set_SysInfo" fullword ascii
        $s13 = "set_Padding" fullword ascii
        $s14 = "set_Success" fullword ascii
        $s15 = "set_Item" fullword ascii
        $s16 = "set_ServerCertificateValidationCallback" fullword ascii
        $s17 = "set_Params" fullword ascii
        $s18 = "set_LocalTime" fullword ascii
        $s19 = "set_CommandType" fullword ascii
        $s20 = "set_TenantId" fullword ascii
        $s21 = "set_KeepAlive" fullword ascii

        $g1 = "get_InvariantCulture" fullword ascii
        $g2 = "get_Value" fullword ascii
        $g3 = "get_Status" fullword ascii
        $g4 = "get_Antivirus" fullword ascii
        $g5 = "get_ComputerName" fullword ascii
        $g6 = "get_RequestPluginName" fullword ascii

        $m1 = "OriginBotnet" ascii
        $m2 = "UpdateBotRequest" ascii
        $m3 = "<Deserialize>b__0" ascii
    condition:
        (uint16(0) == 0x5a4d and (8 of ($s*) or (6 of ($s*) and 4 of ($g*)))) or (2 of ($m*))
}
