rule CryptoStealerGo {
    meta:
        author = "ditekshen"
        description = "CryptoStealerGo payload"
        cape_type = "CryptoStealerGo payload"
    strings:
        $go = "Go build ID: \"" ascii
        $s1 = "file_upload.go" ascii
        $s2 = "grequests.FileUpload" ascii
        $s3 = "runtime.newproc" ascii
        $s4 = "credit_cards" ascii
        $s5 = "zip.(*fileWriter).Write" ascii
        $s6 = "autofill_" ascii
        $s7 = "XFxVc2VyIERhdGFcXA==" ascii
        $s8 = "XFxBcHBEYXRhXFxMb2NhbFxc" ascii
    condition:
        uint16(0) == 0x5a4d and $go and 7 of them
}
