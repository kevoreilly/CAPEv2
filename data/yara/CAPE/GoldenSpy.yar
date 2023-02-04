rule GoldenSpy {
    meta:
        author = "SpiderLabs Trustwave"
        description = "GoldenSpy dropper payload"
        reference = "https://trustwave.azureedge.net/media/16908/the-golden-tax-department-and-emergence-of-goldenspy-malware.pdf"
        cape_type = "GoldenSpy payload"
    strings:
        $reg = "Software\\IDG\\DA" nocase wide ascii // registry entry
        $str1 = "requestStr" nocase wide ascii // POST request the machine details with this parameter
        $str2 = "nb_app_log_mutex" nocase wide ascii // Mutex
        $str3 = { 510F4345[0-10]50518D8DCCFE[0-20]837D1C[0-20]8D45[0-15]0F4345[0-20]505157 } // Data collection and passed to requestStr in POST
    condition:
        (uint16(0) == 0x5A4D) and $reg and 2 of ($str*)
}
