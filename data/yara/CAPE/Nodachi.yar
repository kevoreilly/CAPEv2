rule Nodachi {
    meta:
        author = "ditekSHen"
        description = "Detects Nodachi infostealer"
        cape_type = "Nodachi Payload"
    strings:
        $x1 = "//AppData//Roaming//kavachdb//kavach.db" ascii
        $s1 = "/upload/drive/v3/files/{fileId}" ascii
        $s2 = "main.getTokenFromWeb" ascii
        $s3 = "main.tokenFromFile" ascii
        $s4 = "/goLazagne/" ascii
        $s5 = "/extractor/withoutdrive/main.go" ascii
        $s6 = "struct { Hostname string \"json:\\\"hostname\\\"\"; EncryptedUsername string \"json:\\\"encryptedUsername\\\"\"; EncryptedPassword string \"json:\\\"encryptedPassword\\\"\" }" ascii
        $s7 = "C://Users//public//cred.json" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*)) or (4 of ($s*)))
}
