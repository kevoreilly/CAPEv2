rule Banload {
    meta:
        author = "ditekSHen"
        description = "Detects Banload"
        cape_type = "Banload Payload"
    strings:
        $s1 = "main.die" fullword ascii
        $s2 = "main.postResults" fullword ascii
        $s3 = "main.checkin" fullword ascii
        $s4 = "RegQueryValueExWRemoveDirectoryWSETTINGS_TIMEOUTTerminateProcessUpgrade RequiredUser-Agent: %s" ascii
        $s5 = "pcuser-agentws2_32.dll (targetpc= DigestType ErrCode=%v" ascii
        $s6 = "invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrie" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
