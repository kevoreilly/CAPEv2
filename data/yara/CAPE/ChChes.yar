rule ChChes
{
    meta:
        author = "kev"
        description = "ChChes Payload"
        cape_type = "ChChes Payload"
    strings:
        $payload1 = {55 8B EC 53 E8 ?? ?? FF FF E8 D? FF FF FF 05 ?? ?? ?? 00 33 DB 39 58 44 75 58 56 57 50 E8 57 00 00 00 59 8B F0 E8 A? FF FF FF B9 ?? ?? ?? 00 BF D0 1C ?? 00 2B CF 03 C1 39 5E 30 76 0F}
        $payload2 = {55 8B EC E8 ?? ?? FF FF E8 D? FF FF FF 05 ?? ?? ?? 00 83 78 44 00 75 40 56 57 50 E8 3E 00 00 00 59 8B F0 6A 00 FF 76 30 E8 A8 FF FF FF B9 ?? ?? ?? 00 BF 00 1A E1 00 2B CF 03 C1 50 FF 56 70}
    condition:
        $payload1 or $payload2
}
