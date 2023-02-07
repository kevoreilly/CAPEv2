rule BadRabbit
{
    meta:
        author = "kevoreilly"
        description = "BadRabbit Payload"
        cape_type = "BadRabbit Payload"
    strings:
        $a1 = "caforssztxqzf2nm.onion" wide
        $a2 = "schtasks /Create /SC once /TN drogon /RU SYSTEM" wide
        $a3 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal" wide
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
