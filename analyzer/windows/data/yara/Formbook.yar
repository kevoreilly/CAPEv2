rule Formbook
{
    meta:
        author = "kevoreilly"
        description = "Formbook Anti-analysis Bypass"
        cape_options = "bp0=$remap_ntdll-25,action0=setedx:ntdll,count=0"
    strings:
        $remap_ntdll = {6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B 06 0F 95 C1 84 C9 74 0E 33 C0 B2 FF 00 54 30 ?? 40 83 F8 0D 72 F6}
    condition:
        $remap_ntdll
}
