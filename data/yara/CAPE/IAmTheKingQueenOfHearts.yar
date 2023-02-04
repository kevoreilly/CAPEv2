rule IAmTheKingQueenOfHearts {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing Queen Of Hearts payload"
        cape_type = "IAmTheKingQueenOfHearts Payload"
    strings:
        $s1 = "{'session':[{'name':'" ascii
        $s2 = "begin mainthread ok" wide
        $s3 = "getcommand error" wide
        $s4 = "querycode error" wide
        $s5 = "Code = %d" wide
        $s6 = "cookie size :%d" wide
        $s7 = "send request error:%d" wide
        $s8 = "PmMytex%d" wide
        $s9 = "%s_%c%c%c%c_%d" wide
        $s10 = "?what@exception@std@@UBEPBDXZ" ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
