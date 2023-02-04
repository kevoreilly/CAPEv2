rule Imminent
{
    meta:
        author = "kevoreilly & ditekSHen"
        description = "Imminent Payload"
        cape_type = "Imminent Payload"
    strings:
        $string1 = "Imminent-Monitor"
        $string2 = "abuse@imminentmethods.net"
        $string3 = "SevenZipHelper"
        $string4 = "get_EntryPoint"
        $string5 = "WrapNonExceptionThrows"
        $d1 = "_ENABLE_PROFILING" wide
        $d2 = "Anti-Virus: {0}" wide
        $d3 = "File downloaded & executed" wide
        $d4 = "Chat - You are speaking with" wide
        $d5 = "\\Imminent\\Plugins" wide
        $d6 = "\\Imminent\\Path.dat" wide
        $d7 = "\\Imminent\\Geo.dat" wide
        $d8 = "DisableTaskManager = {0}" wide
        $d9 = "This client is already mining" wide
        $d10 = "Couldn't get AV!" wide
        $d11 = "Couldn't get FW!" wide
    condition:
        uint16(0) == 0x5A4D and (all of ($string*) or 6 of ($d*))
}
