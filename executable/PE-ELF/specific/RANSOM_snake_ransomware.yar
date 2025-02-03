rule snake_ransomware : hardened
{
	meta:
		description = "Rule to detect Snake ransomware"
		author = "McAfee ATR Team"
		date = "2020-02-20"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/EKANS"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		reference = "https://dragos.com/blog/industry-news/ekans-ransomware-and-ics-operations/"
		hash = "e5262db186c97bbe533f0a674b08ecdafa3798ea7bc17c705df526419c168b60"
		score = 75

	strings:
		$snake = { 43 3A 2F 55 73 ?? 72 ?? 2F 57 49 4E 31 2F 67 6F 2F 73 ?? 63 2F 6A 6F 62 6E 68 62 67 6E 6E 69 66 70 6F 64 68 68 70 ?? 6D 66 2F 6E 66 64 6C 68 6F 70 68 6B 65 69 6A 61 64 67 66 64 64 69 6D 2F 6E 66 64 6C 68 6F 70 68 6B 65 69 6A 61 64 67 66 64 64 69 6D 2F 76 74 5F 73 74 ?? 69 6E 67 2E 67 6F 00 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 11000KB ) and all of them
}

rule SnakeRansomware : hardened
{
	meta:
		Author = "Nishan Maharjan"
		Description = "A yara rule to catch snake ransomware"
		Reference = "https://medium.com/@nishanmaharjan17/malware-analysis-snake-ransomware-a0e66f487017"
		Data = "15th May 2020"

	strings:
		$go_build_id = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 58 36 6c 4e 45 70 44 68 63 5f 71 67 51 6c 35 36 78 34 64 75 2f 66 67 56 4a 4f 71 4c 6c 50 43 43 49 65 6b 51 68 46 6e 48 4c 2f 72 6b 78 65 36 74 58 43 67 35 36 45 7a 38 38 6f 74 48 72 7a 2f 59 2d 6c 58 57 2d 4f 68 69 49 62 7a 67 33 2d 69 6f 47 52 7a 22}
		$math_rand_seed_calling = { 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF }
		$encryption_function = {64 8B 0D 14 00 00 00 8B 89 00 00 00 00 3B 61 08 0F 86 38 01 00 00 83 EC 3C E8 32 1A F3 FF 8D 7C 24 28 89 E6 E8 25 EA F0 FF 8B 44 24 2C 8B 4C 24 28 89 C2 C1 E8 1F C1 E0 1F 85 C0 0F 84 FC 00 00 00 D1 E2 89 CB C1 E9 1F 09 D1 89 DA D1 E3 C1 EB 1F 89 CD D1 E1 09 D9 89 CB 81 C1 80 7F B1 D7 C1 ED 1F 81 C3 80 7F B1 D7 83 D5 0D 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF 31 C0 EB 79 89 44 24 20 8B 4C 24 40 8D 14 C1 8B 1A 89 5C 24 24 8B 52 04 89 54 24 1C C7 04 24 05 00 00 00 E8 48 FE FF FF 8B 44 24 08 8B 4C 24 04 C7 04 24 00 00 00 00 8B 54 24 24 89 54 24 04 8B 5C 24 1C 89 5C 24 08 89 4C 24 0C 89 44 24 10 E8 EC DD EF FF 8B 44 24 18 8B 4C 24 14 89 4C 24 08 89 44 24 0C 8B 44 24 24 89 04 24 8B 44 24 1C 89 44 24 04 E8 68 BB F3 FF 8B 44 24 20 40}

	condition:
		all of them
}

