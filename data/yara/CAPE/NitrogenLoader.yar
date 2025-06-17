rule NitrogenLoader
{
    meta:
        author = "enzok"
        description = "Nitrogen Loader"
        cape_type = "NitrogenLoader Loader"
        hash1 = "7b603d63a23201ff0b6ffa9acdd650df9caa1731837d559d93b3d8ce1d82a962"
        hash2 = "50c2afd792bfe2966133ee385054eaae1f73b04e013ef3434ef2407f99d7f037"
        hash3 = "4926dee7da0da522c34ffeebb32f28703fd689a52543332c8d28ccfea223f43a"
    strings:
        $stringaes1 = {63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa}
        $stringaes2 = {52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b}
        $string1 = "GetComputerNameExA"
        $string2 = "LoadResource"
        $syscallmakehashes = {48 89 4C 24 ?? 48 89 54 24 ?? 4? 89 44 24 ?? 4? 89 4C 24 ?? 4? 83 EC ?? B? [4] E8 [3] 00}
        $syscallnumber = {49 89 C3 B? [4] E8 [3] 00}
        $syscall = {48 83 C4 ?? 4? 8B 4C 24 ?? 4? 8B 54 24 ?? 4? 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 89 CA 4? FF E3}
        $decryptstr1 = {33 D2 48 8B 04 24 B? 0C 00 00 00 48 F7 F1 48 8B C2 48 C1 E0 02 0F B6 C8 48 8B 44 24 ?? 48 D3 E8 48 25 AB 00 00 00}
        $decryptrsc1 = {48 63 4? 24 ?? 33 D2 48 [0-3] F7 B4 24 [4] 48 8B C2 48 8B 8C 24 [4] 0F BE 04 01}
        $decryptrsc2 = {8B ?? 24 [1-4] 33 C8 8B C1 48 63 4C 24 ?? 48 8B 94 24 [4] 88 04 0A}
        $decryptrsc3 = {8B 8C 24 ?? ?? ?? ?? 2B C8 8B C1 48 63 4C 24 ?? 48 8B 94 24 [4] 88 04 0A}
        $decryptstrs = {33 D2 48 8B 04 24 B9 0C 00 00 00 48 F7 F1 48 8B C2 48 C1 E0 02 0F B6 C8 48 8B 44 24 ?? 48 D3 E8 48 25 AB 00 00 00}
        $taskman_1 = {E8 [4] B9 61 00 00 00 88 84 24 [4] E8 [4] B9 73 00 00 00 88 84 24 [4] E8 [4] B9 6B 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_2 = {B9 4D 00 00 00 88 84 24 [4] E8 [4] B9 61 00 00 00 88 84 24 [4] E8 [4] B9 6E 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_3 = {B9 61 00 00 00 88 84 24 [4] E8 [4] B9 67 00 00 00 88 84 24 [4] E8 [4] B9 65 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_4 = {B9 72 00 00 00 88 84 24 [4] E8 [4] 31 C9 88 84 24 [4] E8 [3] FF}
        $rc4decrypt_1 = {48 89 ?? 48 89 ?? E8 [4] 48 8B ?? 24 [1-4] 4? 89 ?? 48 89 ?? 4? 89 C1 89 EA E8 [4] 48 89}
        $rc4decrypt_2 = {E8 [4] 8B ?? 24 [1-4] 4? 89 ?? 48 89 ?? 4? 89 C1 E8 [3] FF}
    condition:
        (2 of ($string*) and any of ($syscall*)) or 4 of ($decrypt*) or (3 of ($taskman_*) and all of ($rc4decrypt_*))
}
