rule Retefe
{
    meta:
        author = "Tomasuh"
        description = "Retefe Payload"
        cape_type = "Retefe Payload"
    strings:
        $retefe_encoded_buffer = {48 8b 44 24 20 8b 40 08 48 8b 4c 24 20 48 8d 15}
        $retefe_xor_seed = {24 20 48 8b 44 24 20 C7 40 08}
        $retefe_xor_seed_2ndarg = {89 54 24 10 48 89 4c 24 08 48 83 ec 58 ba}
        $retefe_shift_and_sub_match = {c1 e0 ?? b9}
    condition:
        uint16(0) == 0x5A4D and (all of them)
}
