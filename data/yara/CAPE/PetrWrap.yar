rule PetrWrap
{
    meta:
        author = "kevoreilly"
        description = "PetrWrap Payload"
        cape_type = "PetrWrap Payload"
    strings:
        $a1 = "http://petya3jxfp2f7g3i.onion/"
        $a2 = "http://petya3sen7dyko2n.onion"
        
        $b1 = "http://mischapuk6hyrn72.onion/"
        $b2 = "http://mischa5xyix2mrhd.onion/"
    condition:
        uint16(0) == 0x5A4D and (any of ($a*)) and (any of ($b*))
}
