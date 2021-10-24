rule SingleStepAntiHook
{
    meta:
        author = "kevoreilly"
        description = "Single-step anti-hook Bypass"
        cape_options = "bp0=$antihook+6,action0=skip,count=0"
    strings:
        $antihook = {FF D? 83 EC 08 9C 81 0C 24 00 01 00 00 9D}
    condition:
        any of them
}
