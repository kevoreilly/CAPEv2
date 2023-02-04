rule A310Logger {
    meta:
        author = "ditekSHen"
        description = "Detects A310Logger"
        cape_type = "A310Logger Payload"
    strings:
        $s1 = "Temporary Directory * for" fullword wide
        $s2 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*RD_" wide
        $s3 = "@ENTIFIER=" wide
        $s4 = "ExecQuery" fullword wide
        $s5 = "MSXML2.ServerXMLHTTP.6.0" fullword wide
        $s6 = "Content-Disposition: form-data; name=\"document\"; filename=\"" wide
        $s7 = "CopyHere" fullword wide
        $s8 = "] Error in" fullword wide
        $s9 = "shell.application" fullword wide nocase
        $s10 = "SetRequestHeader" fullword wide
        $s11 = "\\Ethereum\\keystore" fullword wide
        $s12 = "@TITLE Removing" fullword wide
        $s13 = "@RD /S /Q \"" fullword wide
        $en1 = "Unsupported encryption" fullword wide
        $en2 = "BCryptOpenAlgorithmProvider(SHA1)" fullword wide
        $en3 = "BCryptGetProperty(ObjectLength)" fullword wide
        $en4 = "BCryptGetProperty(HashDigestLength)" fullword wide
        // varaint 1
        $v1_1 = "PW\\FILES\\SC::" wide
        $v1_2 = "AddAttachment" fullword wide
        $v1_3 = "Started:" fullword wide
        $v1_4 = "Ended:" fullword wide
        $v1_5 = "sharedSecret" fullword wide
        $v1_6 = "\":\"([^\"]+)\"" fullword wide
        $v1_7 = "\\credentials.txt" fullword wide
        $v1_8 = "WritePasswords" fullword ascii
        $v1_9 = "sGeckoBrowserPaths" fullword ascii
        $v1_10 = "get_sPassword" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (3 of ($en*) and 4 of ($s*)) or (5 of ($s*) and 1 of ($en*)) or 5 of ($v1*) or (4 of ($v1*) and 2 of ($s*) and 2 of ($en*)))
}
