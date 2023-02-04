rule HyperBro {
    meta:
        author = "ditekSHen"
        description = "Detects HyperBro (class names) payload"
        cape_type = "HyperBro Payload"
    strings:
        $s1 = "VTClipboardInfo" ascii wide
        $s2 = "VTClipboardMgr" ascii wide
        $s3 = "VTFileRename" ascii wide
        $s4 = "VTFileRetime" ascii wide
        $s5 = "VTKeyboardInfo" ascii wide
        $s6 = "VTKeyboardMgr" ascii wide
        $s7 = "VTRegeditKeyInfo" ascii wide
        $s8 = "VTRegeditMgr" ascii wide
        $s9 = "VTRegeditValueInfo" ascii wide
        $s10 = "VTFileDataRes" ascii wide
    condition:
        uint16(0) == 0x5a4d and 9 of them
}
