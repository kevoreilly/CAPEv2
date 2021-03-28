rule VBCrypter
{
    meta:
        author = "kevoreilly"
        description = "VBCrypter anti-hook Bypass"
        cape_options = "bp0=$antihook-12,action0=jmp,count=0"
    strings:
        $antihook = {43 39 C3 0F 84 ?? 00 00 00 80 3B B8 75 ?? 83 7B 01 00 75 ?? 80 7B 05 BA 75 ?? 8B 53 06 83 C3 0A 31 C9}
    condition:
        any of them
}
