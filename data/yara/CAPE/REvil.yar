rule REvil
{
    meta:
        author = "R3MRUM"
        description = "REvil Payload"
        cape_type = "REvil Payload"
    strings:
        $RE1 = "expand 32-byte kexpand 16-byte k" ascii fullword
        $RE2 = "sysshadow" ascii fullword
        $RE3 = "SCROLLBAR" ascii fullword
        $RE4 = "msctfime ui" ascii fullword
        $RE5 = "\\BaseNamedObjects\\%S" wide fullword
        $decode = {33 D2 8A 9C 3D FC FE FF FF 8B C7 0F B6 CB F7 75 0C 8B 45 08 0F B6 04 02 03 C6 03 C8 0F B6 F1 8A 84 35 FC FE FF FF 88 84 3D FC FE FF FF 47 88 9C 35 FC FE FF FF 81 FF 00 01 00 00 72 C3}
    condition:
        uint16(0) == 0x5A4D and $decode and any of ($RE*)
}
