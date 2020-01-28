rule REvil
{
    meta:
        author = "R3MRUM"
        description = "REvil Payload"
        cape_type = "REvil Payload"
    strings:
        $OtherRE1 = "expand 32-byte kexpand 16-byte k" ascii fullword
        $OtherRE2 = "sysshadow" ascii fullword
        $OtherRE3 = "SCROLLBAR" ascii fullword
        $OtherRE4 = "msctfime ui" ascii fullword
        $OtherRE5 = "\\BaseNamedObjects\\%S" wide fullword
        $RE_dec = "rwdec_x86_debug.pdb" ascii
        $GCREvil_string_decoder_opcodes = {33 D2 8A 9C 3D FC FE FF FF 8B C7 0F B6 CB F7 75 0C 8B 45 08 0F B6 04 02 03 C6 03 C8 0F B6 F1 8A 84 35 FC FE FF FF 88 84 3D FC FE FF FF 47 88 9C 35 FC FE FF FF 81 FF 00 01 00 00 72 C3 }
        $REvil_string_decoder_opcodes1 = {8B C1 8A 1C 39 33 D2 0F B6 CB F7 75 ?? 8B 45 ?? 0F B6 04 02 03 C6 03 C8 0F B6 F1 8B 4D ?? 8A 04 3E 88 04 39 41 88 1C 3E 89 4D ?? 81 F9 00 01 00 00 }
    condition:
        uint16(0) == 0x5a4d
        and (($GCREvil_string_decoder_opcodes and any of ($OtherRE*)) or any of ($REvil_string_decoder_opcodes*)) and not $RE_dec
}
