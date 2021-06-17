rule Vidar
{
    meta:
        author = "kevoreilly"
        description = "Vidar Payload"
        cape_type = "Vidar Payload"
    strings:
        $trap = {C6 45 ?? 03 E8 [4] 53 6A 01 8D 4D ?? E8 [4] 53 6A 01 8D 4D ?? 88 5D ?? E8 [4] 53 FF 35 [4] 8D 4D ?? E8 [4] 83 F8 FF 74}
        $decode = {FF 75 0C 8D 34 1F FF 15 ?? ?? ?? ?? 8B C8 33 D2 8B C7 F7 F1 8B 45 0C 8B 4D 08 8A 04 02 32 04 31 47 88 06 3B 7D 10 72 D8}
        $wallet = "*walle*.dat"
        $s1 = "\"os_crypt\":{\"encrypted_key\":\"" fullword ascii
        $s2 = "screenshot.jpg" fullword wide
        $s3 = "\\Local State" fullword ascii
        $s4 = "Content-Disposition: form-data; name=\"" ascii
    condition:
        uint16(0) == 0x5A4D and (($decode and $wallet) or (3 of ($s*))) or ($trap)
}
