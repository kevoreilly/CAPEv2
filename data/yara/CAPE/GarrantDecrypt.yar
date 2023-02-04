rule GarrantDecrypt {
    meta:
        author = "ditekSHen"
        description = "Detects GarrantDecrypt ransomware"
        cape_type = "GarrantDecrypt Payload"
    strings:
        $x1 = "%appdata%\\_uninstalling_.png" fullword wide
        $x2 = "C:\\Windows\\sysnative\\vssadmin.exe" fullword wide
        $x3 = /(ICQ|Skype) (@nuncatarde|@supersuso|@Whitehorsedecryption|@likeahorse|@Konwarszawski|@zipzipulya|Whitehorsedecryption|LIKEAHORSE DECRYPTION|Zip Zipulya)/ ascii
        $s1 = "your unique ID" ascii
        $s2 = "Google market ICQ" ascii
        $s3 = "If you want to restore them, install ICQ" ascii
        $s4 = "Write to our ICQ @" ascii
    condition:
        uint16(0) == 0x5a4d and ((2 of ($x*) and 1 of ($s*)) or all of ($s*))
}
