rule Chaos {
    meta:
        author = "ditekSHen"
        description = "Detects Chaos ransomware"
        cape_type = "Chaos Payload"
    strings:
        $s1 = "<EncyptedKey>" fullword wide
        $s2 = "<EncryptedKey>" fullword wide
        $s3 = "C:\\Users\\" fullword wide
        $s4 = "read_it.txt" fullword wide
        $s5 = "#base64Image" fullword wide
        $s6 = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" fullword wide
        $s7 = /check(Spread|Sleep|AdminPrivilage|deleteShadowCopies|disableRecoveryMode|deleteBackupCatalog)/ fullword ascii nocase
        $s8 = /(delete|disable)(ShadowCopies|RecoveryMode|BackupCatalog)/ fullword ascii nocase
        $s9 = "spreadName" fullword ascii
        $s10 = "processName" fullword ascii
        $s11 = "sleepOutOfTempFolder" fullword ascii
        $s12 = "AlreadyRunning" fullword ascii
        $s13 = "random_bytes" fullword ascii
        $s14 = "encryptDirectory" fullword ascii nocase
        $s15 = "EncryptFile" fullword ascii nocase
        $s16 = "intpreclp" fullword ascii
        $s17 = "bytesToBeEncrypted" fullword ascii
        $s18 = "textToEncrypt" fullword ascii
        $m1 = "Chaos is" wide
        $m2 = "Payment informationAmount:" wide
        $m3 = "Coinmama - hxxps://www.coinmama.com Bitpanda - hxxps://www.bitpanda.com" wide
        $m4 = "where do I get Bitcoin" wide
    condition:
        uint16(0) == 0x5a4d and 6 of ($s*) or all of ($m*) or (2 of ($m*) and 4 of ($s*))
}
