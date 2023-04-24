rule capemon
{
    meta:
        author = "kevoreilly"
        description = "capemon yara self-dump prevention"
        string = "CAPE Sandbox"
    strings:
        $hash = {d3 b9 46 1d 9a 14 bc 44 a1 61 c3 47 6a 0e 35 90 00 2c 28 81 dc a0 36 dc 2c 92 0c 7c b6 84 39 59}
    condition:
        all of them
}
