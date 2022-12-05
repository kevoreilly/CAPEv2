import "pe"

rule Nighthawk
{
    meta:
        author = "Nikhil Ashok Hegde <@ka1do9>"
        description = "NightHawk C2"
        cape_type = "Nighthawk Payload"

    strings:
        // Not wildcarding register to have better yara performance
        $keying_methods = { 85 C9 74 43 83 E9 01 74 1C 83 F9 01 0F 85 }

        // AES-128 CBC sbox and inverse-sbox used in key expansion
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 }
        $aes_inv_sbox = { 52 09 6A D5 30 36 A5 38 BF }

    condition:
        pe.is_pe and
        // Nighthawk DLL is known to contain a ".profile" section which
        // contains config
        for any s in pe.sections: (s.name == ".profile") and
        all of them
}
