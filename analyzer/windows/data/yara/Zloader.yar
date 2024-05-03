rule Zloader
{
    meta:
        author = "kevoreilly"
        description = "Zloader API Spam Bypass"
        cape_options = "bp0=$trap1-5,action0=hooks:0,bp1=$traps-108,action1=jmp:15,bp2=$traps-88,action2=hooks:1,count=0"
    strings:
        $trap1 = {81 F7 4C 01 00 00 8D B4 37 [2] FF FF 31 FE 69 FE 95 03 00 00 E8 [4] 31 FE 0F AF FE 0F AF FE E8}
        $traps = {6A 44 53 E8 [2] FF FF 83 C4 08 8D 85 ?? FF FF FF C7 85 ?? FF FF FF 44 00 00 00 50}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Zloader_2024
{
    meta:
        author = "enzok"
        description = "Zloader Registry and Modulename Bypass"
        cape_options = "bp0=$reg_1*+1,bp0=$reg_2*+1,action0=seteax:1,count=0"
    strings:
        $reg_1 = {FF D0 83 F8 00 0F 94 C0 24 01 88 44 24 ?? 4? 8B [3] B? [9-25] E8 [4] 4? 89 F1 FF D0 8A [3] 24 01 0F B6 C0}
        $reg_2 = {B9 [4] E8 [4] 8B [3] 89 C2 E8 [4] 4? [4] ff D0 8A [3] 24 01 0F B6 C0}
        $name_1 = {56 5? 5? 4? 81 EC [4] C7 44 24 ?? 00 00 00 00 4? 8D 0D [4] E8 [4] 4? 89 [3] 4? 83 [3] 00 75}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
