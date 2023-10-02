rule DarkGateLoader
{
    meta:
        author = "enzok"
        description = "DarkGate Loader"
        cape_options = "bp0=$decrypt1+30,bp0=$decrypt2+29,action0=dump:eax::ebx,bp1=$decrypt3+80,action1=dumpsize:eax,bp2=$decrypt3+124,hc2=1,action2=dump:eax,count=0"
        packed = "b15e4b4fcd9f0d23d902d91af9cc4e01417c426e55f6e0b4ad7256f72ac0231a"
    strings:
        $loader = {6C 6F 61 64 65 72}
        $decrypt1 = {B? 01 00 00 00 8B [3] E8 [4] 8B D7 32 54 [4] 88 54 18 FF 4? 4? 75}
        $decrypt2 = {B? 01 00 00 00 8B [2] E8 [4] 8B D7 2B D3 [4] 88 54 18 FF 4? 4? 75}
        $decrypt3 = {89 85 [4] 8B 85 [4] 8B F0 8D BD [4] B? 10 [3] F3 A5 8B 85 [4] 33 D2 [2] 8B 85 [4] 99}
    condition:
        $loader and any of ($decrypt*)
}
