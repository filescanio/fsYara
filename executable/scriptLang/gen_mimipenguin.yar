rule Mimipenguin_SH : hardened
{
	meta:
		description = "Detects Mimipenguin Password Extractor - Linux"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/huntergregal/mimipenguin"
		date = "2017-04-01"
		score = 70
		id = "c670f6fe-562d-598f-a73f-45e4ab234f7d"

	strings:
		$s1 = {24 28 65 63 68 6f 20 24 74 68 69 73 68 61 73 68 20 7c 20 63 75 74 20 2d 64 27 24 27 20 2d 66 20 33 29}
		$s2 = {70 73 20 2d 65 6f 20 70 69 64 2c 63 6f 6d 6d 61 6e 64 20 7c 20 73 65 64 20 2d 72 6e 20 27 2f 67 6e 6f 6d 65 5c 2d 6b 65 79 72 69 6e 67 5c 2d 64 61 65 6d 6f 6e 2f 70 27 20 7c 20 61 77 6b}
		$s3 = {4d 69 6d 69 50 65 6e 67 75 69 6e 20 52 65 73 75 6c 74 73 3a}

	condition:
		1 of them
}

rule mimipenguin_1 : hardened limited
{
	meta:
		description = "Detects Mimipenguin hack tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/huntergregal/mimipenguin"
		date = "2017-07-08"
		hash1 = "9e8d13fe27c93c7571075abf84a839fd1d31d8f2e3e48b3f4c6c13f7afcf8cbd"
		id = "62754337-52ef-5d3f-af2f-52f820ba0476"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 65 6c 66 2e 5f 73 74 72 69 6e 67 73 5f 64 75 6d 70 20 2b 3d 20 73 74 72 69 6e 67 73 28 64 75 6d 70 5f 70 72 6f 63 65 73 73 28 74 61 72 67 65 74 5f 70 69 64 29 29 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 64 65 66 20 5f 64 75 6d 70 5f 74 61 72 67 65 74 5f 70 72 6f 63 65 73 73 65 73 28 73 65 6c 66 29 3a (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 65 6c 66 2e 5f 74 61 72 67 65 74 5f 70 72 6f 63 65 73 73 65 73 20 3d 20 5b 27 73 73 68 64 3a 27 5d (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x4 = {47 6e 6f 6d 65 4b 65 79 72 69 6e 67 50 61 73 73 77 6f 72 64 46 69 6e 64 65 72 28 29}

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 20KB and 1 of them )
}

rule mimipenguin_2 : hardened limited
{
	meta:
		description = "Detects Mimipenguin hack tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/huntergregal/mimipenguin"
		date = "2017-07-08"
		hash1 = "453bffa90d99a820e4235de95ec3f7cc750539e4023f98ffc8858f9b3c15d89a"
		id = "b3bb1ba9-cbfc-53fd-81d0-256466ace4de"

	strings:
		$x1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 44 55 4d 50 3d 24 28 73 74 72 69 6e 67 73 20 22 2f 74 6d 70 2f 64 75 6d 70 2e 24 7b 70 69 64 7d 22 20 7c 20 67 72 65 70 20 2d 45 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 74 72 69 6e 67 73 20 2f 74 6d 70 2f 61 70 61 63 68 65 2a 20 7c 20 67 72 65 70 20 2d 45 20 27 5e 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 20 42 61 73 69 63 2e 2b 3d 24 27 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 72 65 70 20 2d 45 20 27 5e 5f 70 61 6d 6d 6f 64 75 74 69 6c 5f 67 65 74 70 77 6e 61 6d 5f 72 6f 6f 74 5f 31 24 27 20 2d 42 20 35 20 2d 41 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 74 72 69 6e 67 73 20 22 2f 74 6d 70 2f 64 75 6d 70 2e 24 7b 70 69 64 7d 22 20 7c 20 67 72 65 70 20 2d 45 20 2d 6d 20 31 20 27 5e 5c 24 2e 5c 24 2e 2b 5c 24 27 29 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$x5 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 66 20 5b 5b 20 2d 6e 20 24 28 70 73 20 2d 65 6f 20 70 69 64 2c 63 6f 6d 6d 61 6e 64 20 7c 20 67 72 65 70 20 2d 76 20 27 67 72 65 70 27 20 7c 20 67 72 65 70 20 67 6e 6f 6d 65 2d 6b 65 79 72 69 6e 67 29 20 5d 5d 3b 20 74 68 65 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		( uint16( 0 ) == 0x2123 and filesize < 20KB and 1 of them )
}

