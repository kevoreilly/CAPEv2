rule Carbanak
{
    meta:
        author = "enzok"
        description = "Carnbanak Payload"
        cape_type = "Carbanak Payload"
        sample = "c9c1b06cb9c9bd6fc4451f5e2847a1f9524bb2870d7bb6f0ee09b9dd4e3e4c84"
    strings:
        $sboxinit = {0F BE 02 4? 8D 05 [-] 4? 8D 4D ?? E8 [3] 00 33 F6 4? 8D 5D ?? 4? 63 F8 8B 45 ?? B? B1 E3 14 06}
        $decode_string = {0F BE 03 FF C9 83 F8 20 7D ?? B? 1F [3] 4? 8D 4A E2 EB ?? 3D 80 [3] 7D ?? B? 7F [3] 4? 8D 4A A1 EB ?? B? FF [3] 4? 8D 4A 81}
        $constants = {0F B7 05 [3] 00 0F B7 1D [3] 00 83 25 [3] 00 00 89 05 [3] 00 0F B7 05 [3] 00 89 1D [3] 00 89 05 [3] 00 33 C0 4? 8D 4D}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}