rule OLE_VBAPurged_1
{
    meta:
        author = "Fireeye Alyssa Rahman (@ramen0x3f)"
        description = "This file has a _VBA_PROJECT stream that has been cleared. This is evidence of VBA purging, a technique where the p-code (PerformanceCache data) is removed from Office files that have an embedded macro."
    strings:
        $vba_proj = { 5F 00 56 00 42 00 41 00 5F 00 50 00 52 00 4F 00 4A 00 45 00 43 00 54 00 00 00 00 00 00 00 00 00 }
    condition:
        uint32(0) == 0xe011cfd0 and ( uint32(@vba_proj[1] + 0x78) == 0x07 )
}

rule OLE_VBAPurged_2
{
    meta:
        author = "Fireeye Michael Bailey (@mykill), Jonell Baltazar, Alyssa Rahman (@ramen0x3f), Joseph Reyes"
        description = "This file has a suspicious _VBA_PROJECT header and a small _VBA_PROJECT stream. This may be evidence of the VBA purging tool OfficePurge or a tool-generated document."
    strings:
        $vba_proj = { 5F 00 56 00 42 00 41 00 5F 00 50 00 52 00 4F 00 4A 00 45 00 43 00 54 00 00 00 00 00 00 00 00 00 }
        $cc61 = {CC 61 FF FF 00 00 00}
    condition:
        uint32(0) == 0xe011cfd0 and ( uint32(@vba_proj[1] + 0x78) >= 0x07 ) and ( uint32(@vba_proj[1] + 0x78) < 0xff ) and $cc61
}
