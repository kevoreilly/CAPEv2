rule Aspire {
    meta:
        author = "ditekshen"
        description = "Aspire Keylogger payload"
        cape_type = "Aspire payload"
    strings:
        $s1 = "AspireLogger -" wide
        $s2 = "Application: @" wide
        $s3 = "encryptedUsername" wide
        $s4 = "encryptedPassword" wide
        $s5 = "Fetch users fron logins" wide
        $s6 = "URI=file:" wide
        $s7 = "signons.sqlite" wide
        $s8 = "logins.json" wide
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (7 of ($s*))
}
