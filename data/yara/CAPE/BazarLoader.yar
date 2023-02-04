rule BazarLoader {
  meta:
    author = "Rony (@r0ny_123)"
    cape_type = "BazarLoader payload"
    created_date = "2021-08-06"
    revision = "1"
  strings:
    $ = { 0F BE 44 0C ?? 83 E8 ?? 6B C0 [0-2] 41 F7 F9 8D 42 ?? 99 41 F7 F9 88 54 0C ?? 48 FF C1 48 83 F9 }
    $ = { 48 8B 49 [1] E8 [4] FF 15 [4] 4C 8B 43 [1] 33 D2 48 8B C8 FF 15 [4] 48 89 73 [1] 89 73}
  condition:
    uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and any of them
}
