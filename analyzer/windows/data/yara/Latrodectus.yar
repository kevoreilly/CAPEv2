rule Latrodectus
{
    meta:
        author = "kevoreilly"
        description = "Latrodectus export selection"
        cape_options = "export=$export"
        hash = "378d220bc863a527c2bca204daba36f10358e058df49ef088f8b1045604d9d05"
    strings:
        $export = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 30 4C 8B 05 [4] 33 D2 C7 40 [5] 88 50 ?? 49 63 40 3C 42 8B 8C 00 88 00 00 00 85 C9 0F 84}
    condition:
        uint16(0) == 0x5A4D and all of them
}
