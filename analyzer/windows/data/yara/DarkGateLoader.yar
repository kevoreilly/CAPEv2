rule DarkGateLoader
{
    meta:
        author = "enzok"
        description = "DarkGate Loader"
        cape_options = "bp0=$decrypt2+30,action0=dump:eax::ebx,count=0"
        packed = "b15e4b4fcd9f0d23d902d91af9cc4e01417c426e55f6e0b4ad7256f72ac0231a "
    strings:
        $decrypt1 = {B? 01 00 00 00 8B [2] 0F B6 [3] 33 F8 4? 4? 75 ?? 8B 44 24 ?? 8B D5}
        $decrypt2 = {B? 01 00 00 00 8B [3] E8 [4] 8B D7 32 54 1D ?? F6 D2 88 54 18 FF 4? 4? 75}
    condition:
        all of them
}
