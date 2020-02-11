rule Arkei
{
    meta:
        author = "kevoreilly"
        description = "Arkei Payload"
        cape_type = "Arkei Payload"
    strings:
        $string1 = "Windows_Antimalware_Host_System_Worker"
        $string2 = "Arkei"
        $string3 = "Bitcoin\\wallet.dat"
        $string4 = "Ethereum\\keystore"

        $v1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii wide
        $v2 = "/c taskkill /im " fullword ascii
        $v3 = "card_number_encrypted FROM credit_cards" ascii
        $v4 = "\\wallet.dat" ascii
        $v5 = "Arkei/" wide
        $v6 = "files\\passwords." ascii wide
        $v7 = "files\\cc_" ascii wide
        $v8 = "files\\autofill_" ascii wide
        $v9 = "files\\cookies_" ascii wide
    condition:
        uint16(0) == 0x5A4D and (all of ($string*) or 7 of ($v*))
}
