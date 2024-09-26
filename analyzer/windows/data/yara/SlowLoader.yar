rule SlowLoader
{
    meta:
        author = "kevoreilly"
        description = "SlowLoader detonation aide for slow cpus (thread race)"
        cape_options = "break-on-return=CreateProcessA,action0=sleep:1000,count=0"
        packed = "f6eeb73ffb3e6d6cc48f74344cb590614db7e3116ba00a52aefd7dff468a60a5"
    strings:
        $code = {0F B6 44 07 08 0F B6 54 1F 08 03 C2 25 FF 00 00 80 79 07 48 0D 00 FF FF FF 40 89 45 ?? 6A 00}
    condition:
        any of them
}