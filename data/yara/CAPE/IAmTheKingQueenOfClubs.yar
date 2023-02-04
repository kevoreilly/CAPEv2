rule IAmTheKingQueenOfClubs {
    meta:
        author = "ditekSHen"
        description = "IAmTheKing Queen Of Clubs payload"
        cape_type = "IAmTheKingQueenOfClubs Payload"
    strings:
        $s1 = "Not Support!" fullword wide
        $s2 = "%s|%s|%s|%s" fullword wide
        $s3 = "cmd.exe" fullword wide
        $s4 = "for(;;){$S=Get-Content \"%s\";IF($S){\"\" > \"%s\";$t=iex $S 2>\"%s\";$t=$t+' ';echo $t >>\"%s\";}sleep -m " wide
        $s5 = "PowerShell.exe -nop -c %s" fullword wide
        $s6 = "%s \"%s\" Df" fullword wide
        $s7 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
