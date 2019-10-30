rule Cerber
{
    meta:
        author = "kevoreilly"
        description = "Cerber Payload"
        cape_type = "Cerber Payload"
    strings:
        $code1 = {33 C0 66 89 45 8? 8D 7D 8? AB AB AB AB AB [0-2] 66 AB 8D 45 8? [0-3] E8 ?? ?? 00 00} 
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}

