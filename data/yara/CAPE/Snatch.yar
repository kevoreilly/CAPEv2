rule Snatch {
    meta:
        author = "ditekSHen"
        description = "Detects Snatch / GoRansome / MauriGo ransomware"
        cape_type = "Snatch Payload"
    strings:
        $s1 = "main.encryptFile" ascii
        $s2 = "main.encryptFileExt" ascii
        $s3 = "main.deleteShadowCopy" ascii
        $s4 = "main.Shadow" fullword ascii
        $s5 = "main.RecoverMe" fullword ascii
        $s6 = "main.EncryptWithPublicKey" ascii
        $s7 = "main.EncoderLookupDir" fullword ascii
        $s8 = "main.ALIGNUP" fullword ascii
        $s9 = "main.encrypt" fullword ascii
        $s10 = "github.com/mauri870/ransomware" ascii
        $m1 = "Dear You, ALl Your files On YOUR network computers are encrypted" ascii
        $m2 = "You have to pay the ransom of %s USD in bitcoins to the address" ascii
        $m3 = "REMEMBER YOU FILES ARE IN SAVE HANDS AND WILL BE RESTORED OR RECOVERED ONCE PAYMENT IS DONE" ascii
        $m4 = ":HELP FEEED A CHILD:" ascii
        $m5 = ">SYSTEM NETWORK ENCRYPTED<" ascii
        $m6 = "YOUR IDENTIFICATION : %s" ascii
        $m7 = "convince you of our honesty" ascii
        $m8 = "use TOR browser to talk with support" ascii
        $m9 = "encrypted and attackers are taking" ascii
        $p1 = "/Go/src/kitty/kidrives/" ascii
        $p2 = "/LGoGo/encoder.go" ascii nocase
        $p3 = "/Go/src/kitty/kidata/" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or 2 of ($m*) or (1 of ($m*) and 1 of ($s*)) or (all of ($p*) and (1 of ($s*) or 1 of ($m*))))
}
