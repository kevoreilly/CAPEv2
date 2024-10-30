rule NitrogenLoader
{
    meta:
        author = "enzok"
        description = "Nitrogen Loader"
        cape_type = "NitrogenLoader Loader"
        hash = "7b603d63a23201ff0b6ffa9acdd650df9caa1731837d559d93b3d8ce1d82a962"
    strings:
        $aes1 = {63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa}
        $aes2 = {52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b}
        $string1 = "BASS_GetEAXParameters"
        $string2 = "LoadResource"
        $syscallmakehashes = {48 89 4C 24 ?? 48 89 54 24 ?? 4? 89 44 24 ?? 4? 89 4C 24 ?? 4? 83 EC ?? B? [4] E8 [3] 00}
        $syscallnumber = {49 89 C3 B? [4] E8 [3] 00}
        $syscall = {48 83 C4 ?? 4? 8B 4C 24 ?? 4? 8B 54 24 ?? 4? 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 89 CA 4? FF E3}
    condition:
        all of ($aes*) and all of ($string*) and any of ($syscall*)
}
