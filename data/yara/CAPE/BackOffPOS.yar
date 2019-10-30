rule BackOffPOS
{
    meta:
        author = "enzo"
        description = "BackOffPos Payload"
        cape_type = "BackOffPos Payload"
    strings:
        $str1 = "oprat=2&uid=%I64u&uinfo=%s&win=%d.%d&vers=%s"
        $str2 = "&logs="
        $str3 = "&data="
        $str4 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
        $str5 = "Content-Type: application/x-www-form-urlencoded"
    condition:
        all of them
}