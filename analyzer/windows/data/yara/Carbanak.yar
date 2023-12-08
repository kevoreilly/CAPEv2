rule Carbanak
{
    meta:
        author = "enzok"
        description = "Carbanak process dump for config extraction"
        cape_options = "procdump=2"
        packed = "9c9f7174d1c79569ac3464aa9a997d09d44c2094ce1b80a5e63c115edc140c56"
    strings:
        $sboxinit = {0F BE 02 4? 8D 05 [-] 4? 8D 4D ?? E8 [3] 00 33 F6 4? 8D 5D ?? 4? 63 F8 8B 45 ?? B? B1 E3 14 06}
        $decode_string = {0F BE 03 FF C9 83 F8 20 7D ?? B? 1F [3] 4? 8D 4A E2 EB ?? 3D 80 [3] 7D ?? B? 7F [3] 4? 8D 4A A1 EB ?? B? FF [3] 4? 8D 4A 81}
    condition:
        uint16(0) == 0x5A4D and all of them
}