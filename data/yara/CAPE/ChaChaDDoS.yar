rule ChaChaDDoS {
    meta:
        author = "ditekshen"
        description = "ChaChaDDoS variant of XorDDoS payload"
        cape_type = "ChaChaDDoS payload"
    strings:
        $x1 = "[kworker/1:1]" ascii
        $x2 = "-- LuaSocket toolkit." ascii
        $x3 = "/etc/resolv.conf" ascii
        $x4 = "\"macaddress=\" .. DEVICE_MAC .. \"&device=\" .." ascii
        $x5 = "easy_attack_dns" ascii
        $x6 = "easy_attack_udp" ascii
        $x7 = "easy_attack_syn" ascii
        $x8 = "syn_probe" ascii
    condition:
    uint16(0) == 0x457f and 6 of them
}
