rule VBCrypter
{
    meta:
        author = "kevoreilly"
        description = "VBCrypter anti-hook Bypass"
        cape_options = "bp0=$antihook+4,action0=jmp,count=0,no-logs=1"
    strings:
        $antihook = {41 43 3B 13 75 20 66 81 7B FE C9 33 74 06 80 7B FB B9 74 0A C6 43 F9 B8 89 43 FA 40 EB 08}
    condition:
        any of them
}
