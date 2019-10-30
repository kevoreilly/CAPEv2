rule BackOffLoader
{
    meta:
        author = "enzo"
        description = "BackOffLoader Payload"
        cape_type = "BackOffLoader Payload"
    strings:
        $str1 = "uid=%I64u&uinfo=%s&win=%d.%d&bits=%d&vers=%s&build=%s"
        $str2 = "&bots="
        $str3 = "{b:%s|%s}"
        $str4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
    condition:
        all of them
}