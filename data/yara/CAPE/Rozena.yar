rule Rozena
{
    meta:
        cape_type = "Rozena Payload"
    strings:
        $ip_port = {FF D5 6A 0A 68 [4] 68 [4] 89 E6 50 50 50 50 40 50 40 50 68 [4] FF D5}
        $socket = {6A 00 6A 04 56 57 68 [4] FF D5 [0-5] 8B 36 6A 40 68 00 10 00 00 56 6A 00 68}
    condition:
        all of them
}
