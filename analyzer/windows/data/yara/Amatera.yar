rule Amatera
{
    meta:
        author = "kevoreilly"
        description = "Amatera syscall capture"
        cape_options = "sysbp=$sysenter"
        hash = "35eb93548a0c037d392f870c05e0e9fb1aeff3a5a505e1d4a087f7465ed1f6af"
    strings:
        $sysenter = {64 FF 15 C0 00 00 00 C3}
        $harness = {0F B7 55 EC 52 E8 [4] 83 C4 04 C7 45 F0 [4] 8B 45 ?? 50 [0-40] FF 55 F0 83 C4 ?? 8B E5 5D C3}
        $socket = {66 89 [2] 6A 00 6A ?? 8D [3] 68 (03|07) 20 01 00 8B 4D F8 E8 [4] 0F B6 (C0|C8) 85 (C0|C9) 75 04 32 C0 EB}
    condition:
        uint16(0) == 0x5A4D and all of them
}
