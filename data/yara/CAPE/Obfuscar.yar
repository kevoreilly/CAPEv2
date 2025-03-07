rule Obfuscar
{
    meta:
        author = "kevoreilly"
        description = "Obfuscar xor routime"
        // cape_type = "AgentTesla Payload"
        // https://github.com/obfuscar/obfuscar/blob/65e9ced171e0f2a92d2c64c479c3a1ec3624802a/Obfuscar/Obfuscator.cs#L1693
    strings:
        $decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}
    condition:
        uint16(0) == 0x5A4D and any of them
}
