rule AsyncRAT
{
    meta:
        author = "kevoreilly, JPCERT/CC Incident Response Group"
        description = "AsyncRAT Payload"
        cape_type = "AsyncRAT Payload"
    strings:
        $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}
        $b2 = {09 50 00 6F 00 6E 00 67 00 00}
        $string1 = "Pastebin" ascii wide nocase
        $string2 = "Pong" wide
        $string3 = "Stub.exe" ascii wide
        $kitty = "StormKitty" ascii
    condition:
        uint16(0) == 0x5A4D and not $kitty and ($salt and (2 of ($str*) or 1 of ($b*))) or (all of ($b*) and 2 of ($str*))
}

rule AsyncRAT_kingrat {
    meta:
        author = "jeFF0Falltrades"
		cape_type = "AsyncRAT Payload"

    strings:
        $str_async = "AsyncClient" wide ascii nocase
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $str_schtasks = "schtasks /create /f /sc onlogon /rl highest" wide ascii
        $dcrat_1 = "dcrat" wide ascii nocase
        $dcrat_2 = "qwqdan" wide ascii
        $dcrat_3 = "YW1zaS5kbGw=" wide ascii
        $dcrat_4 = "VmlydHVhbFByb3RlY3Q=" wide ascii
        $dcrat_5 = "save_Plugin" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 80 }
        $byte_aes_salt_base = { BF EB 1E 56 FB CD 97 3B B2 19 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }
        $patt_config = { 72 [3] 70 80 [3] 04 }

    condition:
        (not any of ($dcrat*)) and 6 of them and #patt_config >= 10
}
