rule WobbyChipMBR {
    meta:
        author = "ditekSHen"
        description = "Detects WobbyChipMBR / Covid-21 ransomware"
        cape_type = "WobbyChipMBR Payload"
    strings:
        $x1 = "You became a Victim of the Covid-21 Ransomware" ascii wide
        $x2 = "Reinstalling Windows has been blocked" ascii wide
        $x3 = "Enter Decryption Key:" ascii wide
        $x4 = "encrypted with military grade encryption" ascii wide
        $s1 = "schtasks.exe /Create /TN wininit /ru SYSTEM /SC ONSTART /TR" ascii
        $s2 = "\\EFI\\Boot\\bootx64.efi" ascii wide
        $s3 = "DumpHex" fullword ascii
        $s4 = "TFTP Error" fullword wide
        $s5 = "HD(Part%d,MBRType=%02x,SigType=%02x)" fullword wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($x*) or all of ($s*) or (1 of ($x*) and 2 of ($s*)))
}
