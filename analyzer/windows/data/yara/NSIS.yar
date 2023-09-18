rule NSIS
{
    meta:
        author = "kevoreilly"
        description = "NSIS Integrity Check function"
        cape_options = "exclude-apis=LdrLoadDll"
        hash = "d0c1e946f02503a290d24637b5c522145f58372a9ded9e647d24cd904552d235"
    strings:
        $check = {6A 1C 8D 45 [3-8] E8 [4] 8B 45 ?? A9 F0 FF FF FF 75 ?? 81 7D ?? EF BE AD DE 75 ?? 81 7D ?? 49 6E 73 74 75 ?? 81 7D ?? 73 6F 66 74 75 ?? 81 7D ?? 4E 75 6C 6C 75 ?? 09 45 08 8B 45 08 8B 0D [4] 83 E0 02 09 05 [4] 8B 45 ?? 3B C6 89 0D [4] 0F 8? [2] 00 00 F6 45 08 08 75 06 F6 45 08 04 75}
    condition:
        uint16(0) == 0x5A4D and all of them
}
