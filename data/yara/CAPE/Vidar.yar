rule Vidar
{
    meta:
        author = "kevoreilly,rony"
        description = "Vidar Payload"
        cape_type = "Vidar Payload"
        packed = "0cff8404e73906f3a4932e145bf57fae7a0e66a7d7952416161a5d9bb9752fd8"
    strings:
        $decode = {FF 75 0C 8D 34 1F FF 15 ?? ?? ?? ?? 8B C8 33 D2 8B C7 F7 F1 8B 45 0C 8B 4D 08 8A 04 02 32 04 31 47 88 06 3B 7D 10 72 D8}
        $xor_dec = {0F B6 [0-5] C1 E? ?? 33 ?? 81 E? [0-5] 89 ?? 7C AF 06}
        $wallet = "*wallet*.dat" fullword ascii wide
        $s1 = "\"os_crypt\":{\"encrypted_key\":\"" fullword ascii wide
        $s2 = "screenshot.jpg" fullword ascii wide
        $s3 = "\\Local State" fullword ascii wide
        $s4 = "Content-Disposition: form-data; name=\"" fullword ascii wide
        $s5 = "CC\\%s_%s.txt" fullword ascii wide
        $s6 = "History\\%s_%s.txt" fullword ascii wide
        $s7 = "Autofill\\%s_%s.txt" fullword ascii wide
        $s8 = "Downloads\\%s_%s.txt" fullword ascii wide
    condition:
        uint16be(0) == 0x4d5a and 6 of them 
}
