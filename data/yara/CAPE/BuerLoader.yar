rule BuerLoader
{
    meta:
        author = "kevoreilly"
        cape_type = "BuerLoader"
    strings:
        $encode1 = {33 C0 4A 40 3B D0 76 10 56 BE FB FF 00 00 66 01 34 41 40 3B C2 72 F2 5E 5D C3}
        $encode2 = {85 C9 75 03 33 C0 C3 33 D2 8B C1 66 39 11 74 08 83 C0 02 66 39 10 75 F8 2B C1 D1 F8 C3}
        $encode3 = {56 0F B7 32 8B C1 66 85 F6 74 11 2B D1 66 89 30 83 C0 02 0F B7 34 02 66 85 F6 75 F1 33 D2 66 89 10 8B C1 5E C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}
