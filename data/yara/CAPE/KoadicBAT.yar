rule KoadicBAT {
    meta:
        author = "ditekshen"
        description = "Koadic post-exploitation framework BAT payload"
        cape_type = "KoadicBAT payload"
    strings:
        $s1 = "&@cls&@set" ascii
        $s2 = /:~\d+,1%+/ ascii
    condition:
        uint32(0) == 0x4026feff and all of them and #s2 > 100
}
