rule CobaltStrikeBeacon
{
    meta:
      author = "enzo"
      description = "Cobalt Strike Beacon Payload"
      cape_type = "CobaltStrikeBeacon Payload"
    strings:
      $ver3a = { 69 68 69 68 69 6b ?? ?? 69 }
      $ver3b = { 69 69 69 69 }
      $ver4a = { 2e 2f 2e 2f 2e 2c ?? ?? 2e }
      $ver4b = { 2e 2e 2e 2e }
    condition: all of ($ver3*) or all of ($ver4*)
}
