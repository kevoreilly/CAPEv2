rule BumbleBeeLoader
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Loader"
        cape_type = "BumbleBee Loader"
    strings:
        $str_set = {C7 ?? 53 65 74 50}
        $str_path = {C7 4? 04 61 74 68 00}
        $openfile = {48 8B CF 8? 44 24 [0-4] 20 41 FF D4}
        $createsection = {89 44 24 20 FF 93 [2] 00 00 80 BB [2] 00 00 00 8B F? 74}
        $iternaljob = "IternalJob"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule BumbleBee
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Payload"
        cape_type = "BumbleBee Payload"
    strings:
        $antivm = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
	    $str_ua = "bumblebee"
        $str_gate = "/gate"
    condition:
        uint16(0) == 0x5A4D and ($antivm or all of ($str_*))
}
