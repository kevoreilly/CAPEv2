rule Lumma
{
	meta:
		author = "YungBinary"
		description = "Lumma stealer"
		cape_type = "Lumma Payload"
		packed = "5d58bc449693815f6fb0755a364c4cd3a8e2a81188e431d4801f2fb0b1c2de8f"
	strings:
		$chunk_1 = {
			0F B6 14 0E
			89 CF
			83 E7 1F
			0F B6 7C 3C ??
			89 D3
			31 FB
			83 F3 FF
			89 FD
			21 DD
			D1 E5
			29 FD
			29 EA
			8B 5C 24 ??
			88 14 0B
			EB ??
		}

	condition:
		uint16(0) == 0x5a4d and $chunk_1

}
