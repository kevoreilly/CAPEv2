rule IcedID
{
    meta:
        author = "kevoreilly"
        description = "IcedID hook fix"
        cape_options = "ntdll-protect=0"
    strings:
        $hook = {C6 06 E9 83 E8 05 89 46 01 8D 45 ?? 50 FF 75 ?? 6A 05 56 6A FF E8 2D FA FF FF}
    condition:
        any of them
}
