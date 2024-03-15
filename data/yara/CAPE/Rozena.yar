rule Rozena
{
    meta:
        cape_type = "Rozena Payload"
    strings:
        $ip_port = {FF D5 6A 0A 68 [4] 68 [4] 89 E6 50 50 50 50 40 50 40 50 68 [4] FF D5}
    condition:
        all of them
}