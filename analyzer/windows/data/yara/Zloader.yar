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
