rule BumbleBeeLoader
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Loader"
        cape_type = "BumbleBee Loader"
    strings:
        $str_set = {C7 ?? 53 65 74 50}
        $str_path = {C7 4? 04 61 74 68 00}
        $openfile = {48 8B CF [0-18] 8? 44 24 [0-4] 20 41 FF (D4|D5)}
        $createsection = {89 44 24 20 FF 93 [2] 00 00 80 BB [2] 00 00 00 8B F? 74}
        $hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
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
        $antivm1 = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
        $antivm2 = {84 C0 0F 85 [2] 00 00 33 C9 E8 [4] 48 8B C8 E8 [4] 48 8D 85}
	    $str_ua = "bumblebee"
        $str_gate = "/gate"
    condition:
        uint16(0) == 0x5A4D and (any of ($antivm*) or all of ($str_*))
}
