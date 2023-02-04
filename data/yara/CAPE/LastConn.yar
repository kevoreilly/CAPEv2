rule LastConn {
    meta:
        author = "ditekSHen"
        description = "Detects LastConn"
        cape_type = "LastConn Payload"
    strings:
        $s1 = "System.Net.Http.SysSR" fullword wide
        $s2 = "System.Net.Http.WrSR" fullword wide
        $s3 = "yyyy'-'MM'-'dd'T'HH':'mm':'ss.FFFFFFFK" fullword wide
        $s4 = { 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 0c 6e
               00 6f 00 74 00 69 00 66 00 79 00 04 06 12 80 e8
               05 00 00 12 80 e8 08 75 00 73 00 65 00 72 00 08
               74 00 65 00 61 00 6d 00 06 61 00 70 00 70 00 0c
               6e 00 6f 00 61 00 75 00 74 00 68 00 }
        $s5 = { 68 00 69 00 64 00 64 00 65 00 6e 00 10 64 00 69
               00 73 00 61 00 6c 00 6c 00 6f 00 77 00 0e 65 00
               78 00 74 00 65 00 6e 00 64 00 73 00 04 69 00 64
               00 16 75 00 6e 00 69 00 71 00 75 00 65 00 49 00
               74 00 65 00 6d 00 73 }
        $s6 = "<RunFileOnes>d__" ascii
        $s7 = "<UploadFile>d__" ascii
        $s8 = "<ChunkUpload>d__" ascii
        $s9 = "<StartFolder>d__" ascii
        $s10 = "<ReadFileAlw>d__" ascii
        $s12 = "<WriteFileToD>d__" ascii
        $s13 = "<ReadFile>d__" ascii
        $s14 = "<GetUpload>d__" ascii
        $s15 = "CDropbox.Api.DropboxRequestHandler+<RequestJsonStringWithRetry>d__" ascii
    condition:
        uint16(0) == 0x5a4d and 12 of them
}
