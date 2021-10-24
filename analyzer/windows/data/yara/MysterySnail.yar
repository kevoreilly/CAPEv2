rule MysterySnail
{
    meta:
        author = "kevoreilly"
        description = "MysterySnail anti-sandbox bypass"
        cape_options = "bp0=$anti+62,action0=skip,count=0"
    strings:
        $anti = {F2 0F 10 [3] 66 0F 2F 05 [4] 76 0A 8B [3] FF C0 89 [3] B9 5B 05 00 00 FF 15 [4] E8 [4] 89 [3] 8B [3] 8B [3] 2B C8 8B C1 3B [3] 7E 16}
    condition:
        any of them
}
