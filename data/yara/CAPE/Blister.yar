rule Blister
{
    meta:
        author = "kevoreilly"
        description = "Blister Loader"
        cape_type = "Blister Loader"
        hash = "afb77617a4ca637614c429440c78da438e190dd1ca24dc78483aa731d80832c2"
        hash = "d3eab2a134e7bd3f2e8767a6285b38d19cd3df421e8af336a7852b74f194802c"
    strings:
        $protect1 = {50 6A 20 8D 45 ?? 50 8D 45 ?? 50 6A FF FF D7}
        $protect2 = {48 83 C9 FF 48 8D 55 ?? FF D6 48 8D 87 [2] 00 00 48 8D 4D ?? FF D0}
        $lock1 = {B9 FF FF FF 7F 89 75 FC 8B C1 F0 FF 45 FC 83 E8 01 75}
        $lock2 = {B8 FF FF FF 7F 41 BC 01 00 00 00 89 45 40 F0 FF 4D 40 49 2B C4 75}
        $decode = {0F BE C0 49 03 CC 41 33 C1 44 69 C8 [4] 41 8B C1 C1 E8 0F 44 33 C8 8A 01 84 C0 75 E1 41 81 F9 [4] 74}
     condition:
        uint16(0) == 0x5A4D and 2 of them
}
