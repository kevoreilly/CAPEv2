rule OlympicDestroyer
{
    meta:
        author = "kevoreilly"
        description = "OlympicDestroyer Payload"
        cape_type = "OlympicDestroyer Payload"
    strings:
        $string1 = "SELECT origin_url, username_value, password_value FROM logins"    
        $string2 = "API call with %s database connection pointer"    
        $string3 = "os_win.c:%d: (%lu) %s(%s) - %s"    
    condition:
        uint16(0) == 0x5A4D and all of ($string*)
}