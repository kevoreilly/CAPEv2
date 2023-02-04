rule PureLoader {
    meta:
        author = "ditekSHen"
        description = "Detects Pure loader / injector"
        cape_type = "PureLoader Payload"
    strings:
        $s1 = "InvokeMember" fullword wide
        $s2 = "ConcatProducer" fullword wide
        $s3 = ".Classes.Resolver" wide
        $s4 = "get_DLL" fullword ascii
        $s5 = "BufferedStream" fullword ascii
        $s6 = "GZipStream" fullword ascii
        $s7 = "MemoryStream" fullword ascii
        $s8 = "Decompress" fullword ascii
        $s9 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}
