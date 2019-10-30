rule CobaltStrikeBeacon
{
    meta:
      author = "JPCERTCC"
      description = "Cobalt Strike Payload"
      ref = "https://raw.githubusercontent.com/JPCERTCC/aa-tools/master/cobaltstrikescan.py"
      cape_type = "Cobalt Strike Payload"
    strings:
      $v1 = { 73 70 72 6E 67 00 }
      $v2 = { 69 69 69 69 69 69 69 69 }
    condition: $v1 and $v2
}