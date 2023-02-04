rule FoggyWeb {
    meta:
        author = "ditekSHen"
        description = "Detects / Hunts for FoggyWeb"
        cape_type = "FoggyWeb Payload"
    strings:
        $u1 = "/adfs/portal/images/theme/light01/" ascii wide
        $u2 = "/adfs/services/trust/2005/samlmixed/upload" ascii wide
        $s1 = "ProcessGetRequest" ascii wide
        $s2 = "ProcessPostRequest" ascii wide
        $s3 = "UrlGetFileNames" ascii wide
        $s4 = "GetWebpImage" ascii wide
        $s5 = "GetWebpHeader" ascii wide
        $s6 = "ExecuteAssemblyRoutine" ascii wide
        $s7 = "ExecuteBinary" ascii wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
