rule SmokeLoader
{
    meta:
        author = "kevoreilly"
        description = "SmokeLoader Payload"
        cape_options = "bp0=$gate+19,action0=DumpSectionViews,count=1"
    strings:
        $gate = {68 [2] 00 00 50 E8 [4] 8B 45 ?? 89 F1 8B 55 ?? 9A [2] 40 00 33 00 89 F9 89 FA 81 C1 [2] 00 00 81 C2 [2] 00 00 89 0A 8B 46 ?? 03 45 ?? 8B 4D ?? 8B 55 ?? 9A [2] 40 00 33 00}
    condition:
        uint16(0) == 0x5A4D and any of them
}
