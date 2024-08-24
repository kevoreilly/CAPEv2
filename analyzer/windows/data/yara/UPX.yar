rule UPX
{
    meta:
        author = "kevoreilly"
        description = "UPX dump on OEP (original entry point)"
        cape_options = "bp0=$upx32*,bp0=$upx64*,hc0=1,action0=step2oep"
    strings:
        $upx32 = {6A 00 39 C4 75 FA 83 EC ?? E9}
        $upx64 = {6A 00 48 39 C4 75 F9 48 83 EC [1-16] E9}
    condition:
        uint16(0) == 0x5A4D and any of them
}
