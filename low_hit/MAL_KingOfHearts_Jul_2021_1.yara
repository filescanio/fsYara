rule MAL_KingOfHearts_Jul_2021_1 : hardened limited
{
	meta:
		description = "Detect KingOfHearts malware"
		author = "Arkbird_SOLG"
		reference = "https://twitter.com/ShadowChasing1/status/1413111641504292864"
		date = "2021-07-09"
		hash1 = "0639e8f5e517c3f57d28bfd9f51cabfb275c64b7bca224656c2ac04f5a8c3af0"
		hash2 = "0340a90ed4000e579c29f6ad7d4ab2ae1d30f18a2e777689e3e576862efbd6e0"
		hash3 = "393ccb9853ea7628792e4dd982c2dd52dd8f768fdb7b80b20cbfc2fac4e298a4"
		tlp = "White"
		adversary = "IAmTheKing"

	strings:
		$s1 = { 43 00 72 00 65 00 61 00 74 00 65 00 44 00 6f 00 77 00 6e 00 4c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 20 00 22 00 25 00 73 00 22 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 2c 00 45 00 72 00 72 00 6f 00 72 00 3d 00 25 00 64 }
		$s2 = { 43 00 72 00 65 00 61 00 74 00 65 00 55 00 70 00 4c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 20 00 22 00 25 00 73 00 22 }
		$s3 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 42 49 4f 53 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s4 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 5c 31 2d 64 72 69 76 65 72 2d 76 6d 73 72 76 63 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s5 = { 73 74 61 72 74 20 64 6f 77 6e 3a 20 25 73 0a }
		$s6 = { 66 00 69 00 6c 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 20 00 22 00 25 00 73 00 22 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 35KB and 4 of ( $s* )
}

