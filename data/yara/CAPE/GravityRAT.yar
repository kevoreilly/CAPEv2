rule GravityRAT {
    meta:
        author = "ditekSHen"
        description = "Detects GravityRAT"
        cape_type = "GravityRAT Payload"
    strings:
        $s1 = "/GX/GX-Server.php?VALUE=2&Type=" wide
        $s2 = "&SIGNATUREHASH=" wide
        $s3 = "Error => CommonFunctionClass => Upload()" wide
        $s4 = "/GetActiveDomains.php" wide
        $s5 = "DetectVM" ascii wide
        $s6 = "/c {0} > {1}" wide
        $s7 = "DRIVEUPLOADCOMPLETED => TOTALFILES={0}, FILESUPLOADED={1}" wide
        $s8 = "Program => RunAFile()" wide
        $s9 = "DoViaCmd" ascii
        $s10 = ".msoftupdates.com:" wide
        $f1 = "<RootJob>b__" ascii
        $f2 = "<GetFiles>b__" ascii
        $f3 = "<UpdateServer>b__" ascii
        $f4 = "<EthernetId>b__" ascii
        $f5 = "<MatchMacAdd>b__" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($f*) and 1 of ($s*)))
}
