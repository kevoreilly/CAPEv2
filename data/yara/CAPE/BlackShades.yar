rule BlackShades
{
    meta:
        author = "Brian Wallace (@botnet_hunter)"
        ref = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
        family = "blackshades"
        cape_type = "BlackShades Payload"

    strings:
        $string1 = "bss_server"
        $string2 = "txtChat"
        $string3 = "UDPFlood"
    condition:
        all of them
}