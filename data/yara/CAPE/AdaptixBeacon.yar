rule AdaptixBeacon
{
    meta:
        author = "enzok"
        description = "AdaptixBeacon Payload"
        cape_type = "AdaptixBeacon Payload"
    strings:
        $conf_1 = {8D ?? ?? E8 [3] 00 4? 89 [1-2] 4? 8B 4C 24 ?? E8 [3] 00 4? 8B 53 48 66 [0-1] 89 04}
        $conf_2 = {E8 [3] 00 48 8B 4C 24 ?? 48 89 43 78 E8 [3] 00 48 8B 4C 24 ?? 89 83 80 00 00 00 E8 [3] 00 03 83 80 00 00 00 48 8B 4C 24}
        $conf_3 = {E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 58 E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 60 E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 68}
        $wininet_1 = {B9 77 00 00 00 4? 89 50 28 E8 [4] B9 69 00 00 00 88 44 24 ?? E8 [4] B9 6E 00 00 00 88 44 24}
        $wininet_2 = {B9 69 00 00 00 88 44 24 ?? E8 [4] B9 6E 00 00 00 88 44 24 ?? E8 [4] B9 65 00 00 00 88 44 24}
    condition:
        1 of ($conf_*) and 1 of ($wininet_*)
}