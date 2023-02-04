rule Surtr {
    meta:
        author = "ditekSHen"
        description = "Detects Surtr ransomware"
        cape_type = "Surtr Payload"
    strings:
        $s1 = "<title>SurtrRansomware</title>" ascii
        $s2 = "<HTA:APPLICATION ID=\"SurtrRansomware\"" ascii
        $s3 = "APPLICATIONNAME=\"SurtrRansomware\"" ascii
        $s4 = "src=\"data:image/jpeg; base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wCEAAgICAgJCAkKCgkNDgwODRMREBARExwUFhQWFBwrGx8bGx8bKyYuJSMlLiZENS8v" ascii
        $s5 = "4rbgxisigb4pxnloxzc265rmzaj7fslrhyouegtrph2a7xhh55r6xaid.onion" ascii
        $s6 = "schtasks /CREATE /SC ONLOGON /TN svchos" wide
        $s7 = "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ /v \"svchos" ascii
        $s8 = "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\ /v \"svchos" ascii
        $s9 = "SURTR_README.txt" wide
        $s10 = "surtr-decrypt.top" ascii
        $s11 = /(Public|Private|ID)_DATA\.surt/ wide
        // Dropper
        //$d1 = "AES SMALL decryption - %s failed: 0x%08x"
        //$d2 = "Payload successfully decrypted"
        //$d3 = "\\Dev\\source\\repos\\Dropper\\x64\\Release\\Dropper.pdb"
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
