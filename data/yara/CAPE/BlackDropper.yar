rule BlackDropper
{
    meta:
        author = "enzok"
        description = "BlackDropper"
        cape_type = "BlackDropper Payload"
        hash = "f8026ae3237bdd885e5fcaceb86bcab4087d8857e50ba472ca79ce44c12bc257"
    strings:
        $string1 = "BlackDropperCPP"
        $string2 = "Builder.dll"
        $string3 = "\\Builder.exe"
        $crypt1 = {33 D2 48 8B 44 24 ?? 48 8B 4C 24 ?? 48 F7 F1 48 8B C2 48 8B D0 48 8D 4C 24 ?? E8}
        $crypt2 = {0F BE 00 8B 4C 24 ?? 33 C8 8B C1 88 44 24 ?? 48 8B 54 24 ?? 48 8D 4C 24}
        $crypt3 = {E8 [4] 0F B6 4C 24 ?? 88 08 E9}
    condition:
        2 of ($string*) or 2 of ($crypt*)
}