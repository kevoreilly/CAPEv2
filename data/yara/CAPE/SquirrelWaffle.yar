rule SquirrelWaffle
{
    meta:
        author = "kevoreilly & R3MRUM"
        cape_type = "SquirrelWaffle Payload"
    strings:
        $code = {8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39 8D 4D ?? 0F B6 C0 50 6A 01 E8 [4] C6 45}
        $decode = {F7 75 ?? 83 7D ?? 10 8D 4D ?? 8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39}
    condition:
        uint16(0) == 0x5A4D and all of them
}
