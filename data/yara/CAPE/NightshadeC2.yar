rule NightshadeC2
{
  meta:
    author = "YungBinary"
    description = "https://x.com/YungBinary/status/1963751038340534482"
    hash = "963c012d56c62093d105ab5044517fdcce4ab826f7782b3e377932da1df6896d"
    cape_type = "NightshadeC2 Payload"
  strings:
    $s1 = "keylog.txt" wide
    $s2 = "--mute-audio --do-not-de-elevate" wide
    $s3 = "MachineGuid" wide
  condition:
    uint16(0) == 0x5A4D and all of them
}
