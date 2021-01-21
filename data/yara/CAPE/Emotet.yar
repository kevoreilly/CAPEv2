rule Emotet
{
    meta:
        author = "kevoreilly"
        description = "Emotet Payload"
        cape_type = "Emotet Payload"
    strings:
        $snippet5 = {8B E5 5D C3 B8 [4] A3 [4] A3 [4] 33 C0 21 05 [4] A3 [4] 39 05 [4] 74 18 40 A3 [4] 83 3C C5 [4] 00 75 F0 51 E8 [4] 59 C3}
        $snippet6 = {33 C0 21 05 [4] A3 [4] 39 05 [4] 74 18 40 A3 [4] 83 3C C5 [4] 00 75 F0 51 E8 [4] 59 C3}
        $snippet7 = {8B 48 ?? C7 [5-6] C7 40 [4] ?? C7 [2] 00 00 00 [0-1] 83 3C CD [4] 00 74 0E 41 89 48 ?? 83 3C CD [4] 00 75 F2}
        $snippet8 = {85 C0 74 3? B9 [2] 40 00 33 D2 89 ?8 [0-1] 89 [1-2] 8B [1-2] 89 [1-2] EB 0? 41 89 [1-2] 39 14 CD [2] 40 00 75 F? 8B CE E8 [4] 85 C0 74 05 33 C0 40 5E C3}
        $snippet9 = {85 C0 74 4? 8B ?8 [0-1] C7 40 [5] C7 [5-6] C7 40 ?? 00 00 00 00 83 3C CD [4] 00 74 0? 41 89 [2-3] 3C CD [4] 00 75 F? 8B CF E8 [4] 85 C0 74 07 B8 01 00 00 00 5F C3}
        $snippetA = {85 C0 74 5? 8B ?8 04 89 78 28 89 38 89 70 2C EB 04 41 89 48 04 39 34 CD [4] 75 F3 FF 75 DC FF 75 F0 8B 55 F8 FF 75 10 8B 4D EC E8 [4] 83 C4 0C 85 C0 74 05}
        $snippetB = {EB 04 4? 89 [2] 39 [6] 75 F3}
        $snippetC = {EB 03 4? 89 1? 39 [6] 75 F4}
        $comboA1 = {83 EC 28 56 FF 75 ?? BE}
        $comboA2 = {83 EC 38 56 57 BE}
        $comboA3 = {EB 04 40 89 4? ?? 83 3C C? 00 75 F6}
    condition:
        uint16(0) == 0x5A4D and any of ($snippet*) or 2 of ($comboA*)
}