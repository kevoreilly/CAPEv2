rule Quickbind
{
    meta:
        author = "enzok"
        description = "Quickbind"
        cape_type = "Quickbind Payload"
        hash = "bfcb215f86fc4f8b4829f6ddd5acb118e80fb5bd977453fc7e8ef10a52fc83b7"
    strings:
        $sboxinit_1 = {48 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 03 C8 4? 8B C1 0F B6 40 02 89 44 24 ?? 33 D2}
        $sboxinit_2 = {48 8B 44 24 ?? 4? F7 74 24 ?? 4? 8B C2 4? 8B 4C 24 ?? 0F B6 04 01 8B 4C 24 ?? 03 C8 8B C1}
        $crypt_1 = {48 8B 44 24 ?? 0F B6 00 4? 8B 4C 24 ?? 0F B6 44 01 02 4? 8B 4C 24 ?? 0F B6 49 01 4? 8B 54 24}
        $crypt_2 = {88 44 24 ?? 4? 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 03 C8 4? 8B C1 0F B6 00 0F B6 4C 24 ?? 4? 8B 54 24}
    condition:
        any of them
}
