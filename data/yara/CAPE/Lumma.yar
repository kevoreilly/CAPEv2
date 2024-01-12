rule Lumma
{
    meta:
        author = "kevoreilly"
        description = "Lumma config extraction"
        cape_type = "Lumma Payload"
        packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
    strings:
        $c2 = {B8 FF FF FF FF 0F 1F 84 00 00 00 00 00 80 7C [2] 00 8D 40 01 75 F6 C7 44 [2] 00 00 00 00 8D}
        $peb = {8B 44 24 04 85 C0 74 13 64 8B 0D 30 00 00 00 50 6A 00 FF 71 18 FF 15}
        $decode = {88 1F 47 0F B6 19 41 84 DB 75 F5 C6 07 00 0F B6 1E 84 DB 74 16 46 66 2E 0F 1F 84 00 00 00 00 00}
    condition:
        uint16(0) == 0x5a4d and any of them
}
