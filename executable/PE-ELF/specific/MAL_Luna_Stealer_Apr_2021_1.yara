rule MAL_Luna_Stealer_Apr_2021_1 : hardened limited
{
	meta:
		description = "Detect Luna stealer (also Mercurial Grabber)"
		author = "Arkbird_SOLG"
		reference = "https://github.com/NightfallGT/Mercurial-Grabber"
		date = "2021-08-29"
		hash1 = "a14918133b9b818fa2e8728faa075c4f173fa69abc424f39621d6aa1405f5a18"
		hash2 = "93563f68975a858ff07f7eb91f4e0c997f0212d58b1755704d89fecd442d448f"
		hash3 = "0521bb85472869598d9aa822b11edc04044dbe876dbf9900565bfdc8e02c2b21"
		hash4 = "ce35eb5ba2f3f36b3d2742b33d3dbbe95f5ec6b93942ba20be4693528b163e3a"
		tlp = "White"
		adversary = "-"

	strings:
		$s1 = { 73 ?? 00 00 0a 0b 07 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 08 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 6f ?? 00 00 0a 0a 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 06 28 ?? 00 00 0a de 0a 07 2c 06 07 6f ?? 00 00 0a dc de 1a 13 04 72 [2] 00 70 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a de 00 2a }
		$s2 = { 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 0a 02 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 7d ?? 00 00 04 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 0b 02 06 72 [2] 00 70 07 28 ?? 00 00 0a 7d ?? 00 00 04 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 0c 02 72 [2] 00 70 02 7b ?? 00 00 04 72 [2] 00 70 08 28 ?? 00 00 0a 7d ?? 00 00 04 02 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 7d ?? 00 00 04 02 7b ?? 00 00 04 28 ?? 00 00 0a 1f 16 63 21 00 b0 ca a2 4a 01 00 00 58 0d 09 28 ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 13 04 02 12 04 fe 16 ?? 00 00 01 6f ?? 00 00 0a 7d ?? 00 00 04 2a }
		$s3 = { 72 [2] 00 70 73 ?? 00 00 0a 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 2b 75 08 6f ?? 00 00 0a 74 ?? 00 00 01 0b 07 72 [2] 00 70 6f ?? 00 00 0a 2c 16 02 07 72 [2] 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04 07 72 [2] 00 70 6f ?? 00 00 0a 2c 16 02 07 72 [2] 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04 07 72 ?? 19 00 70 6f ?? 00 00 0a 2c 16 02 07 72 ?? 19 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04 08 6f ?? 00 00 0a 2d 83 de 0a 08 2c 06 08 6f ?? 00 00 0a dc 2a }
		$x1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 20 00 6d 00 65 00 72 00 63 00 75 00 72 00 69 00 61 00 6c 00 20 00 67 00 72 00 61 00 62 00 62 00 65 00 72 00 20 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$x2 = { 5c 00 73 00 2a 00 3a 00 5c 00 73 00 2a 00 28 00 22 00 28 00 3f 00 3a 00 5c 00 5c 00 22 00 7c 00 5b 00 5e 00 22 00 5d 00 29 00 2a 00 3f }
		$x3 = { 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 32 00 34 00 7d 00 5c 00 2e 00 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 36 00 7d 00 5c 00 2e 00 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 32 00 37 00 7d 00 01 1d 6d 00 66 00 61 00 5c 00 2e 00 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 38 00 34 00 7d }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20KB and 2 of ( $x* ) and 2 of ( $s* )
}

