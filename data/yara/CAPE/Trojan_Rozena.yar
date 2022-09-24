rule Trojan_Rozena {
    meta:
        author = "vxremalware"
        threat_name = "Linux.Trojan.Rozena"
        scan_context = "file, memory"
        os = "Windows"
    strings:
        $inject = { 89 E1 95 68 A4 1A 70 C7 57 FF D6 6A 10 51 55 FF D0 68 A4 AD }
    condition:
        all of them
}
