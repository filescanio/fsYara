rule APT_APT28_Downdelph_Feb_2021_1 : hardened limited
{
	meta:
		description = "Detect Downdelph used by APT28 group"
		author = "Arkbird_SOLG"
		reference = "https://twitter.com/RedDrip7/status/1362343352759250946"
		date = "2021-02-18"
		hash1 = "ee7cfc55a49b2e9825a393a94b0baad18ef5bfced67531382e572ef8a9ecda4b"

	strings:
		$s1 = { 53 [1-3] 81 c4 [2] ff ff 8b f2 8b ?? 54 8d 44 24 08 50 68 04 01 00 00 8b ?? e8 [12-22] 8d 54 24 04 8b c6 [73-133] 33 d2 52 50 8b 45 e8 8b 55 ec e8 [3] ff 8b 4d 0c 89 01 89 51 04 8b 45 f0 33 d2 52 50 8b 45 e8 8b 55 ec e8 [3] ff 8b 4d 10 89 01 89 51 04 8b c3 5b 8b e5 5d }
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 63 6d 64 2e 65 78 65 20 2f 63 20 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 53 00 61 00 76 00 65 00 20 00 53 00 74 00 72 00 65 00 61 00 6d 00 20 00 25 00 73 00 20 00 69 00 73 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 61 00 73 00 73 00 6f 00 63 00 69 00 61 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 25 00 73 00 3d 00 54 00 68 00 69 00 73 00 20 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 73 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 34 00 2e 00 37 00 30 00 20 00 6f 00 72 00 20 00 67 00 72 00 65 00 61 00 74 00 65 00 72 00 20 00 6f 00 66 00 20 00 43 00 4f 00 4d 00 43 00 54 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = { 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 61 00 79 00 6f 00 75 00 74 00 73 00 5c 00 25 00 2e 00 38 00 78 }
		$s5 = { 4a 00 50 00 45 00 47 00 20 00 65 00 72 00 72 00 6f 00 72 00 20 00 23 00 25 00 64 }
		$s6 = { 45 00 72 00 72 00 6f 00 72 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 3a 00 20 00 25 00 73 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 100KB and 5 of them
}

