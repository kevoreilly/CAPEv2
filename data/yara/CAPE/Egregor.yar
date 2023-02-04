import "pe"

rule Egregor {
    meta:
        author = "ditekSHen"
        description = "Egregor ransomware payload"
        cape_type = "Egregor Payload"
    strings:
        $s1 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" fullword wide
        $p1 = "--deinstall" fullword wide
        $p2 = "--del" fullword wide
        $p3 = "--exit" fullword wide
        $p4 = "--kill" fullword wide
        $p5 = "--loud" fullword wide
        $p6 = "--nooperation" fullword wide
        $p7 = "--nop" fullword wide
        $p8 = "--skip" fullword wide
        $p9 = "--useless" fullword wide
        $p10 = "--yourmommy" fullword wide
        $p11 = "-passegregor" ascii wide
        $p12 = "-peguard" ascii wide
        $p13 = "--nomimikatz" ascii wide
        $p14 = "--multiproc" ascii wide
        $p15 = "--killrdp" ascii wide
        $p16 = "--nonet" ascii wide
        $p17 = "--norename" ascii wide
        $p18 = "--greetings" ascii wide
    condition:
        (uint16(0) == 0x5a4d and pe.is_dll() and ((all of ($s*) and 1 of ($p*)) or
                (
                    2 of them and filesize < 1000KB and
                    for any i in (0 .. pe.number_of_sections) : (
                        (
                            pe.sections[i].name == ".00cfg"
                        )
                    )
                )
            )
        ) or 8 of ($p*)
}
