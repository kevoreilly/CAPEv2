rule DarkCloud {
    meta:
        author = "YungBinary"
        description = "https://x.com/YungBinary/status/1971585972912689643"
        cape_type = "DarkCloud Payload"
    strings:
        $darkcloud1 = "===============DARKCLOUD===============" fullword wide
        $creds1 = "@GateUrl" wide
        $creds2 = "@StrFtpUser" wide
        $creds3 = "@StrFtpPass" wide
        $creds4 = "@StrFtpServer" wide
        $creds5 = "@StrReceiver" wide 
        $creds6 = "@StrSmtpUser" wide
        $creds7 = "@StrSmtpPass" wide
        $sql1 = "SELECT item1 FROM metadata" wide
        $sql2 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" wide
        $sql3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" wide
        $sql4 = "SELECT address FROM ConversationRecipients" wide
        $sql5 = "SELECT address FROM ConversationSenders" wide
        $app1 = "Application : Pidgin" wide
        $app2 = "Application: CoreFTP" wide
        $app3 = "Application: WinSCP" wide
        $app4 = "Application: Outlook" wide
        $app5 = "Application : FileZilla" fullword wide
        $fingerprint1 = "Computer Name: " fullword wide
        $fingerprint2 = "OS FullName: " fullword wide
        $fingerprint3 = "CPU: " fullword wide
        $fingerprint4 = "SELECT * FROM Win32_Processor" fullword wide
        $fingerprint5 = "SELECT * FROM Win32_OperatingSystem" fullword wide
    condition:
        uint16(0) == 0x5a4d and 
        (
            $darkcloud1 and 1 of ($creds*) or 
            (3 of ($creds*) and 1 of ($sql*)) or 
            (2 of ($sql*) and 2 of ($app*)) or 
            (2 of ($creds*) and 2 of ($fingerprint*)) or 
            (2 of ($app*) and 2 of ($fingerprint*) and 1 of ($sql*))
        )
}
