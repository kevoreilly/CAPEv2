rule Hello {
    meta:
        author = "ditekSHen"
        description = "Hunt for Hello / WickrMe ransomware"
        cape_type = "Hello Payload"
    strings:
        $s1 = "DeleteBackupFiles" ascii wide
        $s2 = "GetEncryptFiles" ascii wide
        $s3 = "DeleteVirtualDisks" ascii wide
        $s4 = "DismountVirtualDisks" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
