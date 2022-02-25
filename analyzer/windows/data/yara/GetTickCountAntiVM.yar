rule GetTickCountAntiVM
{
    meta:
        author = "kevoreilly"
        description = "GetTickCountAntiVM bypass"
        cape_options = "bp0=$antivm1-13,bp0=$antivm5-40,bp0=$antivm6,action0=wret,hc0=1,bp1=$antivm2-6,action1=wret,hc1=1,count=1,bp2=$antivm3+42,action2=jmp:96,bp3=$antivm4-9,action3=wret,hc3=1"
        hash = "662bc7839ed7ddd82d5fdafa29fafd9a9ec299c28820fe4104fbba9be1a09c42"
        hash = "00f1537b13933762e1146e41f3bac668123fac7eacd0aa1f7be0aa37a91ef3ce"
        hash = "549bca48d0bac94b6a1e6eb36647cd007fed5c0e75a0e4aa315ceabdafe46541"
        hash = "90c29a66209be554dfbd2740f6a54d12616da35d0e5e4af97eb2376b9d053457"
    strings:
        $antivm1 = {57 FF D6 FF D6 BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm2 = {F2 0F 11 45 ?? FF 15 [4] 6A 00 68 10 27 00 00 52 50 E8 [4] 8B C8 E8 [4] F2 0F 59 45}
        $antivm3 = {0F 57 C0 E8 [4] 8B 35 [4] BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm4 = {F2 0F 11 45 EC FF 15 [4] 8B DA 8B C8 BA [4] 89 5D FC F7 E2 BF [4] 89 45 F4 8B F2 8B C1 B9}
        $antivm5 = {BB 01 00 00 00 8B FB 90 FF 15 [4] FF C7 66 0F 6E C7 F3 0F E6 C0 66 0F 2F F8 73 EA}
        $antivm6 = {48 81 EC 88 00 00 00 0F 57 C0 F2 0F 11 44 [2] F2 0F 10 05 [4] F2 0F 11 44 [2] F2 0F 10 05 [4] F2 0F 11}
    condition:
        any of them
}
