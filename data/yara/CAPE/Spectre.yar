rule Spectre {
    meta:
        author = "ditekSHen"
        description = "Detects Spectre infostealer"
        cape_type = "Spectre Infostealer Payload"
    strings:
        $s1 = "\\../../../json.h" wide
        $s2 = "static_cast<std::size_t>(index) < kCachedPowers.size()" fullword wide
        $s3 = " cmd.exe" fullword wide
        $s4 = "m_it.object_iterator != m_object->m_value.object->end()" fullword wide
        $h1 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword wide
        $h2 = "----974767299852498929531610575" ascii wide
        $h3 = "Content-Disposition: form-data; name=\"file\"; filename=\"" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and ((all of ($s*) and 1 of ($h*)) or (all of ($h*) and 2 of ($s*)))) or (6 of them)
}
