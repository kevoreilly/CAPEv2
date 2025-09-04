rule NightshadeC2
{
  meta:
    author = "YungBinary"
    description = "Detects unpacked NightshadeC2, see X"
    hash = "963c012d56c62093d105ab5044517fdcce4ab826f7782b3e377932da1df6896d"
  strings:
    $a = "camera!" wide
    $b = "keylog.txt" wide
    $c = "--mute-audio --do-not-de-elevate" wide
    $d = "MachineGuid" wide
  condition:
    uint16(0) == 0x5A4D and all of them
}