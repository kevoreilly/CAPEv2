rule Al_khaser
{
    meta:
        author = "kevoreilly"
        description = "Al-khaser bypass"
        cape_options = "bp0=$print_check_result_x86,bp0=$print_check_result_x64,action0=setecx:0,count=1,no-logs=2"
    strings:
        $print_check_result_x86 = {89 45 FC 53 56 8B C1 89 95 C4 FD FF FF 89 85 C8 FD FF FF 57 6A F5 83 F8 01 75 47 FF 15 [4] 8B D8 8D 8D E4 FD FF FF BA 16 00 00 00 66 90}
        $print_check_result_x64 = {48 89 84 24 50 02 00 00 8B F1 83 F9 01 B9 F5 FF FF FF 48 8B EA 75 41 FF 15 [4] 48 8D 7C 24 30 B9 16 00 00 00 48 8B D8}
    condition:
        uint16(0) == 0x5A4D and any of ($print_check_result*)
}
