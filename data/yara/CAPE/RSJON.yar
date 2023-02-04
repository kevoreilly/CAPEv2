rule RSJON {
    meta:
        author = "ditekSHen"
        description = "Detects RSJON / Ryzerlo / HiddenTear ransomware"
        cape_type = "RSJON Payload"
    strings:
        $pdb1 = "C:\\Users\\brknc\\source\\repos\\" ascii
        $pdb2 = "\\rs-jon\\obj\\Debug\\rs-jon.pdb" ascii
        $pdb3 = "\\rs-jon\\obj\\Release\\rs-jon.pdb" ascii
        $x1 = "READ_ME_PLZ.txt" wide
        $x2 = "Files has been encrypted with rs-jon" wide
        $x3 = ".rsjon" wide
        $x4 = "bitcoins or kebab" wide
        $x5 = /rs[-_]jon/ fullword ascii wide
        $s1 = "SPIF_UPDATEINIFILE" fullword ascii
        $s2 = "SPI_SETDESKWALLPAPER" fullword ascii
        $s3 = "bytesToBeEncrypted" fullword ascii // Same as Apsotle
        $s4 = "SendPassword" fullword ascii
        $s5 = "EncryptFile" ascii
        $s6 = "fWinIni" fullword ascii
        $s7 = "BTCAdress" fullword ascii
        $s8 = "self_destruck" fullword ascii // Simialr to Apsotle (SelfDelete)
        $c1 = "?computer_name=" wide
        $c2 = "&serialnumber=" wide
        $c3 = "&password=" wide
        $c4 = "&allow=ransom" wide
        $c5 = "://darkjon.tk/" wide
        $c6 = "/rnsm/write.php" wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or 6 of ($s*) or 4 of ($c*) or (2 of ($c*) and 4 of ($s*)) or (1 of ($pdb*) and 1 of them))
}
