rule Epsilon {
    meta:
        author = "ditekSHen"
        description = "Detects Epsilon ransomware"
        cape_type = "Epsilon Payload"
    strings:
        $s1 = ".Speak \"" wide
        $s2 = "chkUpdateRegistry" fullword wide
        $s3 = "/C choice /C Y /N /D Y /T 1 & Del \"" fullword wide
        $s4 = "CreateObject(\"sapi.spvoice\")" fullword wide
        $s5 = "READ_ME.hta" wide
        $s6 = "WScript.Sleep(" wide
        $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
        $s8 = "<div class='bold'>Files are encrypted* but not deleted.</div>" ascii
        $e1 = { 72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00
                78 00 65 00 00 09 2e 00 74 00 78 00 74 00 00 09
                2e 00 64 00 6f 00 63 00 00 0b 2e 00 64 00 6f 00
                63 00 78 00 00 09 2e 00 78 00 6c 00 73 00 00 0d
                2e 00 69 00 6e 00 64 00 65 00 78 00 00 09 2e 00
                70 00 64 00 66 00 00 09 2e 00 7a 00 69 00 70 00
                00 09 2e 00 72 00 61 00 72 00 00 09 2e 00 63 00
                73 00 73 00 00 09 2e 00 6c 00 6e 00 6b 00 00 0b
                2e 00 78 00 6c 00 73 00 78 00 00 09 2e 00 70 00
                70 00 74 00 00 0b 2e 00 70 00 70 00 74 00 78 00
                00 09 2e 00 6f 00 64 00 }
        $e2 = { 68 00 74 00 6d 00 00 07 2e 00 6d 00 6c 00 00 07
                43 00 3a 00 5c 00 00 07 44 00 3a 00 5c 00 00 07
                45 00 3a 00 5c 00 00 07 46 00 3a 00 5c 00 00 07
                47 00 3a 00 5c 00 00 07 5a 00 3a 00 5c 00 00 07
                41 00 3a 00 5c 00 00 0f 63 00 6d 00 64 00 2e 00
                65 00 78 00 65 }
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (all of ($e*) and 4 of ($s*)))
}
