rule HKTL_Nim_NimPackt : EXE FILE HKTL hardened limited
{
	meta:
		description = "Detects binaries generated with NimPackt v1"
		author = "Cas van Cooten"
		reference = "https://github.com/chvancooten/NimPackt-v1"
		date = "2022-01-26"
		score = 80
		id = "3399d937-133f-5701-840e-eaf68b2f1ec9"

	strings:
		$nim1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 66 61 74 61 6c 2e 6e 69 6d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$nim2 = {77 69 6e 69 6d}
		$np1 = { 4E 69 6D 50 61 63 6B 74 }
		$sus1 = { 61 6D 73 69 00 00 00 00 B8 57 00 07 80 C3 }
		$sus2 = { 5B 2B 5D 20 49 6E 6A 65 63 74 65 64 }
		$sus3 = { 5C 2D 2D 20 62 79 74 65 73 20 77 72 69 74 74 65 6E 3A }

	condition:
		uint16( 0 ) == 0x5A4D and filesize < 750KB and 1 of ( $nim* ) and ( $np1 or 2 of ( $sus* ) )
}

