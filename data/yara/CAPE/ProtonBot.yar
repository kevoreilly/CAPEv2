rule ProtonBot {
    meta:
        author = "ditekSHen"
        description = "Detects ProtonBot loader"
        cape_type = "ProtonBot Payload"
    strings:
        $x1 = "\\PROTON\\Release\\build.pdb" ascii
        $x2 = "\\proton\\proton bot\\json.hpp" wide
        $x3 = "proton bot" ascii wide
        $s1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s2 = "ranges.size() == 2 or ranges.size() == 4 or ranges.size() == 6" fullword wide
        $s3 = "ref_stack.back()->is_array() or ref_stack.back()->is_object()" fullword wide
        $s4 = "ktmw32.dll" fullword ascii
        $s5 = "@detail@nlohmann@@" ascii
        $s6 = "urlmon.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (all of ($s*) and 1 of ($x*)))
}
