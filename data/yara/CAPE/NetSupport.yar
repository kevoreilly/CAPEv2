rule NetSupport {
    meta:
        author = "ditekSHen"
        description = "Detects NetSupport client"
        cape_type = "NetSupport Payload"
    strings:
        $s1 = ":\\nsmsrc\\nsm\\" fullword ascii
        $s2 = "name=\"NetSupport Client Configurator\"" fullword ascii
        $s3 = "<description>NetSupport Manager Remote Control.</description>" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}
