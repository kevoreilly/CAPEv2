rule SmokeInjector
{
    meta:
        author = "kevoreilly"
        cape_options = "monitor=explorer"
        packed = "d38f9ab81a054203e5b5940e6d34f3c8766f4f4104b14840e4695df511feaa30"
    strings:
        $dec1 = {80 04 08 [0-7] (49|83 E9 01) [0-7] 41 [0-7] 81 F1 [2] 00 00 [0-7] 01 D9 [0-7] FF E1}
    condition:
        uint16(0) == 0x5A4D and any of them
}
