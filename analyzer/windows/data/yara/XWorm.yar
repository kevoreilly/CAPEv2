rule XWorm
{
    meta:
        author = "kevoreilly"
        description = "XWorm Config Extractor"
        cape_options = "bp0=$decrypt+11,action0=string:r10,count=1,typestring=XWorm Config"
    strings:
        $decrypt = {45 33 C0 39 09 FF 15 [4] 48 8B F0 E8 [4] 48 8B C8 48 8B D6 48 8B 00 48 8B 40 68 FF 50 ?? 90}
    condition:
        any of them
}
