rule IAmTheKing {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing payload"
        cape_type = "IAmTheKing Payload"
    strings:
        $s1 = "DeleteFile \"%s\" Failed,Err=%d" wide
        $s2 = "DeleteFile \"%s\" Success" wide
        $s3 = "ExcuteFile \"%s\" Failed,Err=%d" wide
        $s4 = "ExcuteFile \"%s\" Success" wide
        $s5 = "CreateDownLoadFile \"%s\" Failed,Error=%d" wide
        $s6 = "uploadFile \"%s\" Failed,errorcode=%d" wide
        $s7 = "CreateUpLoadFile \"%s\" Success" wide
        $s8 = "im the king" ascii
        $s9 = "dont disturb me" fullword ascii
        $s10 = "kill me or love me" fullword ascii
        $s11 = "please leave me alone" fullword ascii
        $s12 = "calculate the NO." fullword ascii
        $s13 = "\\1-driver-vmsrvc" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 7 of them
}
