rule AdaptixBeacon
{
    meta:
        author = "enzok"
        description = "AdaptixBeacon Payload"
        cape_type = "AdaptixBeacon Payload"
        hash = "f78f5803be5704420cbb2e0ac3c57fcb3d9cdf443fbf1233c069760bee115b5d"
    strings:
        $conf_1 = {8D ?? ?? E8 [3] 00 4? 89 [1-2] 4? 8B 4C 24 ?? E8 [3] 00 4? 8B 53 48 66 [0-1] 89 04 ?? E8}
        $conf_2 = {E8 [3] 00 48 8B 4C 24 ?? 48 89 43 78 E8 [3] 00 48 8B 4C 24 ?? 89 83 80 00 00 00 E8 [3] 00 03 83 80 00 00 00 48 8B 4C 24}
        $conf_3 = {E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 58 E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 60 E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 68}
        $conf_4 = {8D ?? ?? 4? 89 ?? FF ?? 4? 89 ?? 4? 89 ?? 4? 8B ?? FF ?? ?? 4? 8B ?? 48 66 ?? 89 ?? ?? EB}
        $conf_5 = {48 89 ?? 4? 89 ?? FF ?? 4? 89 ?? 4? 89 D9 4? 89 ?? ?? 4? 8B 03 FF ?? ?? 4? 89 ?? 4? 89 ?? 4? 89 ?? ?? 4? 8B 03 FF ?? ?? 4? 89}
        $wininet_1 = {B9 77 00 00 00 [0-4] E8 [4] B9 69 00 00 00 88 ?4 24 [0-4] E8 [4] B9 6E 00 00 00 88 ?4 24}
        $wininet_2 = {B9 69 00 00 00 88 ?4 24 [0-4] E8 [4] B9 6E 00 00 00 88 ?4 24 [0-4] E8 [4] B9 65 00 00 00 88 ?4 24}
    condition:
        1 of ($conf_*) and 1 of ($wininet_*)
}
