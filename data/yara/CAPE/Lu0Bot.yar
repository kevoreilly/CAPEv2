rule Lu0Bot
{
    meta:
        author = "ditekSHen, @Fmk0, @r0ny123"
        description = "Detects Lu0Bot"
        cape_type = "Lu0Bot Payload"
        modified_date = "2021-12-14"
    strings:
        /*
        81 c7 cc 01 00 00    add        edi, 0x1cc
        81 2e 4b 4b 4d 4c    sub        dword ptr [esi], 0x4c4d4b4b
        83 c6 04             add        esi, 4
        39 fe                cmp        esi, edi
        7c f3                jl         0x40110e
        */
        $s = { 81 c7 [4] 81 2e [4] 83 c6 ?? 39 fe 7c }
    condition:
        uint16be(0) == 0x4D5A and uint32be(uint32(0x3C)) == 0x50450000 and filesize < 5KB and all of them
}
