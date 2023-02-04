rule IAmTheKingScrCap {
    meta:
        author = "ditekshen"
        description = "IAmTheKing screen capture payload"
        cape_type = "IAmTheKingScrCap Payload"
    strings:
        $s1 = "@MyScreen.jpg" fullword wide
        $s2 = "DISPLAY" fullword wide
        $s3 = ".?AVCImage@ATL@@" fullword ascii
        $s4 = ".?AVGdiplusBase@Gdiplus@@" fullword ascii
        $s5 = ".?AVImage@Gdiplus@@" fullword ascii
        $s6 = ".?AVBitmap@Gdiplus@@" fullword ascii
        $s7 = ".?AVCAtlException@ATL@@" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
