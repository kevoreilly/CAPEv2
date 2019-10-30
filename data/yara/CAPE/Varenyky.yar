rule Varenyky
{
    meta:
        author = "kevoreilly"
        description = "Varenyky Payload"
        cape_type = "Varenyky Payload"
    strings:
        $onion = "jg4rli4xoagvvmw47fr2bnnfu7t2epj6owrgyoee7daoh4gxvbt3bhyd.onion"
    condition:
        uint16(0) == 0x5A4D and ($onion)
}
