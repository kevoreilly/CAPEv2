import "pe"

rule NetSupport
{
  meta:
    author = "YungBinary"
    description = "Detects NetSupport Manager RAT on disk or in memory"
    cape_type = "NetSupport Payload"
  strings:
    $a1 = "NetSupport Manager" wide
    $b1 = "NetSupport Remote Control" wide
    $s1 = "Client Application" wide
    $s2 = "NetSupport Ltd" wide
  condition:
    uint16(0) == 0x5a4d and ((pe.imports("PCICL32.dll", "_NSMClient32@8")) or (($a1 and $b1) or ($s1 and $s2)))
}
