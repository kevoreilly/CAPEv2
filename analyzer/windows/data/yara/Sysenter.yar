rule Sysenter
{
    meta:
        cape_options = "clear,dump,sysbp=$sysenterA,sysbp=$sysenterB+10"
    strings:
        $sysenterA = {64 FF 15 C0 00 00 00 C3}
        $sysenterB = {B8 [3] 00 BA [4] FF D2 C?}
    condition:
        any of them
}
