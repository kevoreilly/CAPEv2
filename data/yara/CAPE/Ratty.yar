rule Ratty {
    meta:
        author = "ditekshen"
        description = "Detects Ratty Java RAT"
        cape_type = "Ratty Payload"
    strings:
        $s1 = "/rat/RattyClient.class" ascii
        $s2 = "/rat/ActiveConnection.class" ascii
        $s3 = "/rat/attack/" ascii
        $s4 = "/rat/gui/swing/Ratty" ascii
        $s5 = "/rat/packet/PasswordPacket" ascii
        $s6 = "/rat/packet/" ascii
        $e1 = "/engine/Keyboard.class" ascii
        $e2 = "/engine/IMouseListener.class" ascii
        $e3 = "/engine/Screen$ResizeBehavior.class" ascii
        $e4 = "/engine/fx/ISoundListener.class" ascii
        $e5 = "/engine/net/TCPServer.class"  ascii
        $e6 = "/engine/noise/PerlinNoise.class" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xcfd0 or uint16(0) == 0x4b50) and (3 of ($s*) or all of ($e*))
}
