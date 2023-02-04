rule W1RAT {
    meta:
        author = "ditekshen"
        description = "W1 RAT payload"
        cape_type = "W1 RAT payload"
    strings:
        $s1 = "/c /Ox /Fa\"%s/%s.asm\" /Fo\"%s/%s.obj\" \"%s/%s.%s\"" ascii
        $s2 = "this->piProcInfo.hProcess" fullword ascii
        $s3 = "index >= 0 && index < this->reg_tab->GetLen()" fullword ascii
        $s4 = "strcpy(log_font.lfFaceName,\"%s\");" fullword ascii
        $s5 = "WorkShop -- [%s]" fullword ascii
        $s6 = "HeaderFile.cpp" fullword ascii
        $s7 = "WndLog.cpp" fullword ascii
        $s8 = "assertion fail \"%s\" at file=%s line=%d" fullword ascii
        $s9 = "Stdin   pipe   creation   failed" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (all of them)
}
